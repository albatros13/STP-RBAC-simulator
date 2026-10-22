"""Run the STP-RBAC authorisation predicate on Open Policy Agent (OPA/Rego).

The rules live in ``policies/stprbac.rego`` and are policy-independent; a
concrete policy Theta is shipped to OPA as data under ``data.policy``. This
module converts a :class:`Policy` to that data document and evaluates requests
in one of two ways:

  * :class:`OpaCli`    -- local, one ``opa eval`` process per call;
  * :class:`OpaServer` -- the OPA REST API of an ``opa run --server`` instance
    (started by :func:`opa_server` or running elsewhere).

Both return the same decision documents (see the header of the .rego file), so
they can be checked against :mod:`stprbac.engine` request by request.
Standard library only, like the rest of the core.
"""
from __future__ import annotations

import contextlib
import json
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Iterator

from .intervals import IntervalSet
from .model import Policy, Request

REGO_FILE = Path(__file__).resolve().parent.parent / "policies" / "stprbac.rego"
PACKAGE_PATH = "stprbac/authz"     # data.stprbac.authz
ENTRY_POINTS = ("decision", "coordinator", "worker")


# ---------------------------------------------------------------------------
# Policy -> OPA data document
# ---------------------------------------------------------------------------
def _ivs(iv: IntervalSet) -> list[list[int]]:
    return [[a, b] for a, b in iv.intervals]


def _nested(m: dict[tuple[str, str], object], conv) -> dict[str, dict[str, object]]:
    out: dict[str, dict[str, object]] = defaultdict(dict)
    for (a, b), v in sorted(m.items()):
        out[a][b] = conv(v)
    return dict(out)


def policy_to_opa_data(policy: Policy) -> dict:
    """The ``data.policy`` document for policies/stprbac.rego.

    Pair-keyed relations become nested objects so that Rego can index them
    directly (``P.pa[r][o]``); Gamma becomes an adjacency map. Only what Auth
    reads is exported: SoD is a whole-policy property, not a conjunct.
    """
    gamma: dict[str, list[str]] = defaultdict(list)
    for a, b in sorted(policy.gamma):
        gamma[a].append(b)
    return {
        "roles": sorted(policy.roles),
        "ua": _nested(policy.ua, _ivs),
        "pa": _nested(policy.pa, _ivs),
        "h": _nested(policy.h, _ivs),
        "rho_u": {k: sorted(v) for k, v in sorted(policy.rho_u.items())},
        "rho_g": {k: sorted(v) for k, v in sorted(policy.rho_g.items())},
        "rho_s": {k: sorted(v) for k, v in sorted(policy.rho_s.items())},
        "gamma": dict(gamma),
        "pi": _nested(policy.pi, sorted),
        "delta": {k: sorted(v) for k, v in sorted(policy.delta.items())},
    }


def write_bundle(policy: Policy, out_dir: str | Path) -> Path:
    """Write ``stprbac.rego`` + ``data.json`` into ``out_dir``.

    The directory can be loaded as is: ``opa run --server out_dir`` or
    ``opa eval -d out_dir ...``. Returns the directory path.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(REGO_FILE, out / REGO_FILE.name)
    (out / "data.json").write_text(
        json.dumps({"policy": policy_to_opa_data(policy)}, indent=2) + "\n",
        encoding="utf-8")
    return out


def request_to_input(q: Request, *, with_purpose: bool = True) -> dict:
    """Request -> OPA input. The coordinator phase can omit ``p`` entirely."""
    d = {"u": q.u, "r": q.r, "o": q.o, "p": q.p, "l": q.l, "t": q.t}
    if not with_purpose:
        del d["p"]
    return d


def _input_for(q: Request, entry: str) -> dict:
    return request_to_input(q, with_purpose=(entry != "coordinator"))


# ---------------------------------------------------------------------------
# Local evaluation: `opa eval`
# ---------------------------------------------------------------------------
class OpaCli:
    """Evaluate with the ``opa`` binary; nothing to start or stop.

    Each call spawns one process (tens of milliseconds), so use
    :meth:`decide_many` for more than a handful of requests.
    """

    def __init__(self, policy: Policy, opa: str = "opa"):
        if shutil.which(opa) is None:
            raise FileNotFoundError(f"OPA binary {opa!r} not found on PATH")
        self.opa = opa
        self._dir = tempfile.TemporaryDirectory(prefix="stprbac-opa-")
        write_bundle(policy, self._dir.name)

    def close(self) -> None:
        self._dir.cleanup()

    def __enter__(self) -> "OpaCli":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _eval(self, rule: str, input_doc: dict):
        query = f"data.{PACKAGE_PATH.replace('/', '.')}.{rule}"
        proc = subprocess.run(
            [self.opa, "eval", "--format", "json", "--stdin-input",
             "--data", self._dir.name, query],
            input=json.dumps(input_doc), capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"opa eval failed: {proc.stderr or proc.stdout}")
        result = json.loads(proc.stdout).get("result")
        if not result:
            raise RuntimeError(f"opa eval: {query} is undefined")
        return result[0]["expressions"][0]["value"]

    def decide(self, q: Request, entry: str = "decision") -> dict:
        return self._eval(entry, _input_for(q, entry))

    def decide_many(self, qs: Iterable[Request]) -> list[dict]:
        """Full decisions for many requests in a single ``opa eval`` run."""
        reqs = [request_to_input(q) for q in qs]
        return self._eval("batch", {"requests": reqs})


# ---------------------------------------------------------------------------
# Remote evaluation: OPA REST API
# ---------------------------------------------------------------------------
class OpaServer:
    """Client for a running OPA server (``opa run --server``).

    :meth:`load` pushes the rules and a policy through the Policy and Data
    APIs, so one server can be re-pointed at a different Theta at run time.
    """

    def __init__(self, url: str = "http://127.0.0.1:8181", timeout: float = 10.0):
        self.url = url.rstrip("/")
        self.timeout = timeout

    def _call(self, method: str, path: str, body: bytes | None = None,
              content_type: str = "application/json"):
        req = urllib.request.Request(f"{self.url}{path}", data=body, method=method,
                                     headers={"Content-Type": content_type})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"OPA {method} {path}: {exc.code} {exc.read().decode()}") from exc
        return json.loads(raw) if raw else {}

    def healthy(self) -> bool:
        try:
            self._call("GET", "/health")
            return True
        except (OSError, RuntimeError):
            return False

    def load(self, policy: Policy) -> None:
        self._call("PUT", "/v1/policies/stprbac", REGO_FILE.read_bytes(), "text/plain")
        self._call("PUT", "/v1/data/policy", json.dumps(policy_to_opa_data(policy)).encode())

    def _query(self, rule: str, input_doc: dict):
        out = self._call("POST", f"/v1/data/{PACKAGE_PATH}/{rule}",
                         json.dumps({"input": input_doc}).encode())
        if "result" not in out:
            raise RuntimeError(f"OPA: data.{PACKAGE_PATH}/{rule} is undefined "
                               "(rules or data not loaded?)")
        return out["result"]

    def decide(self, q: Request, entry: str = "decision") -> dict:
        return self._query(entry, _input_for(q, entry))

    def decide_many(self, qs: Iterable[Request]) -> list[dict]:
        return self._query("batch", {"requests": [request_to_input(q) for q in qs]})


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def opa_server(policy: Policy, port: int | None = None, opa: str = "opa",
               startup_timeout: float = 10.0) -> Iterator[OpaServer]:
    """Start an empty local ``opa run --server``, load ``policy`` over the REST
    API, and stop the server on exit."""
    if shutil.which(opa) is None:
        raise FileNotFoundError(f"OPA binary {opa!r} not found on PATH")
    port = port or _free_port()
    proc = subprocess.Popen(
        [opa, "run", "--server", "--addr", f"127.0.0.1:{port}", "--log-level", "error"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    client = OpaServer(f"http://127.0.0.1:{port}")
    try:
        deadline = time.monotonic() + startup_timeout
        while not client.healthy():
            if proc.poll() is not None:
                raise RuntimeError(f"opa exited: {proc.stderr.read().decode()}")
            if time.monotonic() > deadline:
                raise TimeoutError("OPA server did not become healthy")
            time.sleep(0.05)
        client.load(policy)
        yield client
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        proc.stderr.close()

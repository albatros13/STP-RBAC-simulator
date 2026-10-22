#!/usr/bin/env python3
"""Launch a full STP-RBAC federation on localhost: one Central node and N Workers.

Each node runs as its own uvicorn process on its own port, so the topology
mirrors a real deployment where the coordinator and the regional data providers
are independent services (in reality, in different regions).

Usage:
    python run_federation.py                       # default pharma/hospital scenario
    python run_federation.py --scenario scenarios.pharma_hospital
    python run_federation.py --central-port 9000 --base-worker-port 9001

Ctrl-C tears the whole federation down.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx

from stprbac.serde import policy_to_dict

RUNTIME_DIR = Path(__file__).parent / ".runtime"


def _wait_healthy(url: str, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(f"{url}/health", timeout=1.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.25)
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Launch an STP-RBAC federation on localhost.")
    ap.add_argument("--scenario", default="scenarios.pharma_hospital",
                    help="module exposing build_policy() and default_topology()")
    ap.add_argument("--central-port", type=int, default=None)
    ap.add_argument("--base-worker-port", type=int, default=None,
                    help="if set, workers are assigned consecutive ports from here")
    args = ap.parse_args()

    scenario = importlib.import_module(args.scenario)
    policy = scenario.build_policy()
    topo = scenario.default_topology()

    if args.central_port is not None:
        topo["central"]["port"] = args.central_port
    if args.base_worker_port is not None:
        for i, w in enumerate(topo["workers"]):
            w["port"] = args.base_worker_port + i

    # Serialise the approved policy so every node loads an identical copy.
    RUNTIME_DIR.mkdir(exist_ok=True)
    policy_file = RUNTIME_DIR / "policy.json"
    policy_file.write_text(json.dumps(policy_to_dict(policy), indent=2), encoding="utf-8")

    central = topo["central"]
    central_url = f"http://{central['host']}:{central['port']}"

    procs: list[subprocess.Popen] = []

    def spawn(module_app: str, port: int, extra_env: dict) -> subprocess.Popen:
        env = os.environ.copy()
        env["POLICY_FILE"] = str(policy_file)
        env.update(extra_env)
        cmd = [sys.executable, "-m", "uvicorn", module_app,
               "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"]
        return subprocess.Popen(cmd, env=env)

    def shutdown(*_):
        print("\n[launcher] shutting down federation ...")
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print(f"[launcher] scenario: {args.scenario}")
    print(f"[launcher] starting coordinator at {central_url} ...")
    procs.append(spawn("federation.central:app", central["port"],
                       {"PORT": str(central["port"])}))
    if not _wait_healthy(central_url):
        print("[launcher] coordinator failed to start", file=sys.stderr)
        shutdown()

    for w in topo["workers"]:
        self_url = f"http://{w['host']}:{w['port']}"
        print(f"[launcher] starting worker '{w['node_id']}' "
              f"(region {w['region']}) at {self_url} ...")
        procs.append(spawn(
            "federation.worker:app", w["port"],
            {
                "NODE_ID": w["node_id"],
                "REGION": w["region"],
                "OBJECTS": ",".join(w["objects"]),
                "CENTRAL_URL": central_url,
                "SELF_URL": self_url,
                "PORT": str(w["port"]),
            },
        ))
        _wait_healthy(self_url)

    print("\n[launcher] federation is up:")
    print(f"    coordinator : {central_url}")
    for w in topo["workers"]:
        print(f"    worker      : http://{w['host']}:{w['port']}  "
              f"{w['node_id']} ({w['region']}) -> {w['objects']}")
    print(f"\n[launcher] policy written to {policy_file}")
    print("[launcher] try:  python demo_client.py")
    print("[launcher] Ctrl-C to stop.\n")

    # Supervise: if any child dies, bring everything down.
    while True:
        for p in procs:
            if p.poll() is not None:
                print(f"[launcher] a node exited (pid {p.pid}, code {p.returncode})",
                      file=sys.stderr)
                shutdown()
        time.sleep(0.5)


if __name__ == "__main__":
    raise SystemExit(main())

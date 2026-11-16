"""JSON (de)serialisation for Policy so it can travel between nodes over HTTP.

Policies -- unlike data -- are shared across the federation: the coordinator
distributes an approved policy to the nodes. A policy has tuple keys, frozensets
and IntervalSet values that plain JSON cannot hold, so we convert explicitly.
Round-tripping is exact.

The small converters (:func:`intervals_to_json`, :func:`setmap_to_json`) are
also used by :mod:`stprbac.rego` for the OPA data document.
"""
from __future__ import annotations

import json
from pathlib import Path

from .intervals import IntervalSet
from .model import Policy


# ---- shared converters ----------------------------------------------------
def intervals_to_json(iv: IntervalSet) -> list[list[int]]:
    return [[a, b] for a, b in iv.intervals]


def intervals_from_json(raw: list[list[int]]) -> IntervalSet:
    return IntervalSet((a, b) for a, b in raw)


def setmap_to_json(m: dict[str, frozenset[str]]) -> dict[str, list[str]]:
    """{key: frozenset} -> {key: sorted list}, keys in sorted order."""
    return {k: sorted(v) for k, v in sorted(m.items())}


def setmap_from_json(raw: dict[str, list[str]]) -> dict[str, frozenset[str]]:
    return {k: frozenset(v) for k, v in raw.items()}


def _pairmap_to_json(m: dict[tuple[str, str], IntervalSet]) -> list[dict]:
    return [{"key": [k[0], k[1]], "iv": intervals_to_json(v)} for k, v in m.items()]


def _pairmap_from_json(raw: list[dict]) -> dict[tuple[str, str], IntervalSet]:
    return {(e["key"][0], e["key"][1]): intervals_from_json(e["iv"]) for e in raw}


# ---- Policy <-> dict --------------------------------------------------------
def policy_to_dict(p: Policy) -> dict:
    return {
        "users": sorted(p.users),
        "roles": sorted(p.roles),
        "objects": sorted(p.objects),
        "labels": sorted(p.labels),
        "purposes": sorted(p.purposes),
        "ua": _pairmap_to_json(p.ua),
        "pa": _pairmap_to_json(p.pa),
        "h": _pairmap_to_json(p.h),
        "rho_u": setmap_to_json(p.rho_u),
        "rho_g": setmap_to_json(p.rho_g),
        "rho_s": setmap_to_json(p.rho_s),
        "gamma": [[a, b] for a, b in sorted(p.gamma)],
        "pi": [{"key": [k[0], k[1]], "purposes": sorted(v)} for k, v in p.pi.items()],
        "delta": setmap_to_json(p.delta),
        "sod": [sorted(pair) for pair in p.sod],
    }


def policy_from_dict(d: dict) -> Policy:
    return Policy(
        users=frozenset(d["users"]),
        roles=frozenset(d["roles"]),
        objects=frozenset(d["objects"]),
        labels=frozenset(d["labels"]),
        purposes=frozenset(d["purposes"]),
        ua=_pairmap_from_json(d["ua"]),
        pa=_pairmap_from_json(d["pa"]),
        h=_pairmap_from_json(d["h"]),
        rho_u=setmap_from_json(d["rho_u"]),
        rho_g=setmap_from_json(d["rho_g"]),
        rho_s=setmap_from_json(d["rho_s"]),
        gamma=frozenset((a, b) for a, b in d["gamma"]),
        pi={(e["key"][0], e["key"][1]): frozenset(e["purposes"]) for e in d["pi"]},
        delta=setmap_from_json(d["delta"]),
        sod=frozenset(frozenset(pair) for pair in d["sod"]),
    )


# ---- files -----------------------------------------------------------------
def write_json(doc: object, path: str | Path) -> Path:
    """Write ``doc`` as indented JSON (UTF-8, trailing newline); return the path."""
    out = Path(path)
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return out


def save_policy(p: Policy, path: str | Path) -> Path:
    return write_json(policy_to_dict(p), path)


def load_policy(path: str | Path) -> Policy:
    return policy_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

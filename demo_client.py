#!/usr/bin/env python3
"""Drive a running federation with a batch of access requests.

Start the federation first:   python run_federation.py
Then in another terminal:      python demo_client.py

Each request is annotated with the outcome we expect and the phase/node that
should decide it, so the run doubles as a readable end-to-end check of the
two-phase architecture.
"""
from __future__ import annotations

import argparse
import json

import httpx

# (description, request, expected-summary)
CASES = [
    ("Authorised: EU clinician reads EHR for care",
     dict(u="alice", r="clinician", o="ehr", p="care", l="EU", t=50),
     "AUTH at eu-hospital"),

    ("Authorised via hierarchy: coordinator inherits clinician's EHR permission",
     dict(u="erin", r="coordinator_role", o="ehr", p="care", l="EU", t=50),
     "AUTH at eu-hospital (inherited permission)"),

    ("Denied at COORDINATOR (activation): auditor is not active outside phase 4",
     dict(u="dan", r="auditor", o="consent", p="audit", l="CH", t=150),
     "DENY at coordinator / activation"),

    ("Denied at COORDINATOR (locus): US analyst declaring an EU locus",
     dict(u="carol", r="analyst", o="genome", p="research", l="EU", t=150),
     "DENY at coordinator / locus"),

    ("Denied at COORDINATOR (spatial): US locus may not touch EU-governed report",
     dict(u="carol", r="analyst", o="report", p="reporting", l="US", t=250),
     "DENY at coordinator / spatial (cross-border)"),

    ("Denied at WORKER (purpose): data manager may anonymise EHR, not use it for care",
     dict(u="bob", r="data_manager", o="ehr", p="care", l="UK", t=50),
     "DENY at eu-hospital / purpose"),
]


def render(decision: dict) -> str:
    lines = []
    verdict = "AUTHORISED" if decision["authorised"] else "DENIED"
    lines.append(f"  -> {verdict}  (decided at: {decision['decided_at']})")
    for ph in decision["phases"]:
        conj = ", ".join(f"{k}={'T' if v else 'F'}" for k, v in ph["conjuncts"].items())
        mark = "pass" if ph["passed"] else f"FAIL@{ph['first_failure']}"
        lines.append(f"     [{ph['enforcement_point']:<11}] {mark:<18} {conj}")
    if decision.get("output"):
        lines.append(f"     output: {decision['output']}")
    if decision.get("denial"):
        d = decision["denial"]
        lines.append(f"     denial: {d['message']}")
        lines.append(f"             responsible: {d['responsible_elements']}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--central", default="http://127.0.0.1:9000")
    ap.add_argument("--json", action="store_true", help="dump raw JSON decisions")
    args = ap.parse_args()

    print(f"nodes registered with coordinator {args.central}:")
    try:
        nodes = httpx.get(f"{args.central}/nodes", timeout=5.0).json()
    except Exception as exc:
        print(f"  cannot reach coordinator ({exc}). Is run_federation.py running?")
        return 1
    for nid, r in nodes.items():
        print(f"  {nid:<14} region={r['region']:<3} objects={r['objects']}")
    print()

    with httpx.Client(timeout=10.0) as client:
        for desc, req, expected in CASES:
            resp = client.post(f"{args.central}/request", json=req)
            decision = resp.json()
            print(f"* {desc}")
            print(f"  q = {req}   (expected: {expected})")
            if args.json:
                print(json.dumps(decision, indent=2))
            else:
                print(render(decision))
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

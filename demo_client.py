#!/usr/bin/env python3
"""Drive a running federation with a batch of access requests.

Start the federation first:   python run_federation.py
Then in another terminal:      python demo_client.py

Each request (scenarios.pharma_hospital.DEMO_CASES) is annotated with the
outcome we expect and the phase/node that should decide it, so the run doubles
as a readable end-to-end check of the two-phase architecture.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict

import httpx

from scenarios.pharma_hospital import DEMO_CASES
from stprbac.diagnose import format_phase


def render(decision: dict) -> str:
    verdict = "AUTHORISED" if decision["authorised"] else "DENIED"
    lines = [f"  -> {verdict}  (decided at: {decision['decided_at']})"]
    lines += [format_phase(ph["enforcement_point"], ph) for ph in decision["phases"]]
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

    failed = 0
    with httpx.Client(timeout=10.0) as client:
        for case in DEMO_CASES:
            req = asdict(case.request)
            resp = client.post(f"{args.central}/request", json=req)
            print(f"* {case.description}")
            print(f"  q = {req}   (expected: {case.expected})")
            if resp.status_code != 200:
                failed += 1
                print(f"  -> HTTP {resp.status_code}: {resp.text}\n")
                continue
            decision = resp.json()
            print(json.dumps(decision, indent=2) if args.json else render(decision))
            print()
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

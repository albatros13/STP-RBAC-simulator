#!/usr/bin/env python3
"""Evaluate a scenario's policy on Open Policy Agent instead of the Python engine.

    python run_opa.py export                  # write policies/scenarios/<name>/data.json
    python run_opa.py demo                    # demo requests via `opa eval` (local)
    python run_opa.py demo --server           # same, via a throwaway `opa run --server`
    python run_opa.py demo --url http://127.0.0.1:8181   # via an OPA server you run
    python run_opa.py serve --port 8181       # keep an OPA server up with the scenario loaded

Rules: policies/stprbac.rego. Every decision is checked against stprbac.engine.
"""
from __future__ import annotations

import argparse
import importlib
import json
import signal
import sys
import time
from dataclasses import asdict
from pathlib import Path

from stprbac import engine, rego
from stprbac.diagnose import format_phase


def data_file(scenario: str) -> Path:
    return rego.REGO_FILE.parent / "scenarios" / scenario.rsplit(".", 1)[-1] / "data.json"


def demo(policy, cases, client, as_json: bool) -> int:
    mismatches = 0
    for case in cases:
        q = case.request
        pre = client.decide(q, "coordinator")        # coordinator never sees q.p
        post = client.decide(q, "worker") if pre["passed"] else None
        full = client.decide(q)
        agrees = (full["allow"] == engine.auth(policy, q)
                  and full["conjuncts"] == engine.evaluate_conjuncts(policy, q))
        mismatches += not agrees
        print(f"* {case.description}\n  q = {asdict(q)}   (expected: {case.expected})")
        if as_json:
            print(json.dumps({"coordinator": pre, "worker": post, "decision": full}, indent=2))
        else:
            print(f"  -> {'AUTHORISED' if full['allow'] else 'DENIED'}"
                  + ("" if full["allow"] else f"  (first failure: {full['first_failure']})"))
            print(format_phase("coordinator", pre))
            print(format_phase("worker", post))
            print(f"     engine agrees: {'yes' if agrees else 'NO'}")
        print()
    print(f"{len(cases) - mismatches}/{len(cases)} decisions agree with stprbac.engine")
    return 1 if mismatches else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--scenario", default="scenarios.pharma_hospital",
                    help="module exposing build_policy() and, for `demo`, DEMO_CASES")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("export", help="write the scenario's OPA data document")
    d = sub.add_parser("demo", help="send the demo requests to OPA")
    where = d.add_mutually_exclusive_group()
    where.add_argument("--server", action="store_true",
                       help="start a temporary local OPA server and use its REST API")
    where.add_argument("--url", help="use an already running OPA server (rules and "
                                     "data are pushed to it first)")
    d.add_argument("--json", action="store_true", help="dump raw OPA decisions")
    s = sub.add_parser("serve", help="run an OPA server with the scenario loaded")
    s.add_argument("--port", type=int, default=8181)
    args = ap.parse_args()

    scenario = importlib.import_module(args.scenario)
    policy = scenario.build_policy()
    cases = getattr(scenario, "DEMO_CASES", ())

    if args.cmd == "export":
        print(f"wrote {rego.write_data(policy, data_file(args.scenario))}")
        return 0

    if args.cmd == "serve":
        # SIGTERM -> KeyboardInterrupt, so the OPA child is always stopped
        signal.signal(signal.SIGTERM, signal.default_int_handler)
        example = json.dumps({"input": asdict(cases[0].request) if cases else {}})
        with rego.opa_server(policy, port=args.port) as client:
            print(f"[opa] serving {args.scenario} at {client.url}  (Ctrl-C to stop)\n"
                  f"[opa] try:\n  curl -s {client.url}/v1/data/stprbac/authz/decision \\\n"
                  f"    -d '{example}'", flush=True)
            try:
                while client.healthy():
                    time.sleep(1)
            except KeyboardInterrupt:
                return 0
        print("[opa] server stopped", file=sys.stderr)
        return 1

    if args.url:
        client = rego.OpaServer(args.url)
        client.load(policy)
        print(f"[opa] REST API at {args.url}\n")
        return demo(policy, cases, client, args.json)
    if args.server:
        with rego.opa_server(policy) as client:
            print(f"[opa] temporary REST server at {client.url}\n")
            return demo(policy, cases, client, args.json)
    with rego.OpaCli(policy) as client:
        print("[opa] local `opa eval`\n")
        return demo(policy, cases, client, args.json)


if __name__ == "__main__":
    raise SystemExit(main())

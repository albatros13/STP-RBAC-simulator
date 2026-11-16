#!/usr/bin/env python3
"""Compare the Z3 encoding (stprbac/smt.py) with the direct engine (stprbac/engine.py).

Part 1 checks that they agree; part 2 times them.

    python -m bench.compare_smt              # full run, writes bench/results/compare_smt.json
    python -m bench.compare_smt --quick      # smaller sweep

Engine baselines for the analysis queries enumerate time, because the engine
only answers ground requests:

  * ``enum``:        every integer t in [min endpoint, max endpoint]. Exact
                     and independent of any breakpoint argument; this is the
                     agreement oracle.
  * ``breakpoints``: only the lower endpoints of all validity intervals, which
                     is exact by the argument in the smt.py docstring
                     (Lemma 3). The fair algorithmic baseline.
"""
from __future__ import annotations

import argparse
import itertools
import json
import random
import statistics
import time
from dataclasses import replace
from pathlib import Path

import z3

from bench import machine
from generators.synthetic import Knobs, generate, random_request, random_small
from scenarios.pharma_hospital import build_policy
from stprbac import engine, smt
from stprbac.intervals import IntervalSet, always
from stprbac.model import Policy, Request

RESULTS = Path(__file__).parent / "results"


# ---------------------------------------------------------------------------
# Engine-based baselines for the existential queries
# ---------------------------------------------------------------------------
def all_ivs(p: Policy):
    return (iv for rel in p.temporal_relations().values() for iv in rel.values())


def instants(p: Policy, how: str) -> list[int]:
    ends = [e for iv in all_ivs(p) for e in iv.endpoints()]
    if not ends:
        return []
    if how == "enum":
        return list(range(min(ends), max(ends) + 1))
    return sorted({a for iv in all_ivs(p) for a, _ in iv.intervals})


def engine_find_access(p: Policy, pat: smt.AccessPattern, how: str) -> Request | None:
    ts = [t for t in instants(p, how) if pat.admits_time(t)]
    if pat.t_from is not None and how == "breakpoints":
        ts = sorted(set(ts) | {pat.t_from})
    for (u, r, o, pp, l) in itertools.product(*pat.domains(p)):
        for t in ts:
            q = Request(u, r, o, pp, l, t)
            if engine.auth(p, q):
                return q
    return None


def engine_dead(p: Policy, how: str) -> list[tuple[str, str, str]]:
    return [(r, o, pp) for (r, o) in sorted(p.pa) for pp in sorted(p.pi_of(r, o))
            if engine_find_access(p, smt.AccessPattern(r=r, o=o, p=pp), how) is None]


def engine_sod(p: Policy, how: str) -> set[tuple[str, tuple[str, str]]]:
    out = set()
    ts = instants(p, how)
    for u in sorted(p.users):
        for pair in sorted(tuple(sorted(x)) for x in p.sod):
            if any(set(pair) <= engine.act_t(p, u, t) for t in ts):
                out.add((u, pair))
    return out


def scale_time(p: Policy, k: int) -> Policy:
    """Stretch every endpoint by k: same structure, k-times longer horizon."""
    s = lambda m: {key: IntervalSet((a * k, b * k) for a, b in iv.intervals)  # noqa: E731
                   for key, iv in m.items()}
    return replace(p, ua=s(p.ua), pa=s(p.pa), h=s(p.h))


def timed(fn, *args):
    start = time.perf_counter()
    out = fn(*args)
    return out, time.perf_counter() - start


def pct(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


# ---------------------------------------------------------------------------
# Part 1: agreement
# ---------------------------------------------------------------------------
def agreement(n_policies: int, n_requests: int) -> dict:
    res = {"requests": 0, "conjunct_mismatch": 0, "fixedpoint_mismatch": 0,
           "find_access": 0, "find_access_mismatch": 0,
           "dead_policies": 0, "dead_mismatch": 0,
           "sod_policies": 0, "sod_mismatch": 0, "sod_bad_witness": 0,
           "repairs_attempted": 0, "repairs_found": 0, "repairs_infeasible": 0,
           "repair_unsound": 0}
    for seed in range(n_policies):
        rng = random.Random(seed)
        p = random_small(rng)
        se, fe = smt.SmtEngine(p), smt.FixedpointEngine(p)

        for _ in range(n_requests):
            q = random_request(p, rng, 100)
            res["requests"] += 1
            ref = engine.evaluate_conjuncts(p, q)
            if se.evaluate_conjuncts(q) != ref:
                res["conjunct_mismatch"] += 1
            if fe.auth(q) != all(ref.values()):
                res["fixedpoint_mismatch"] += 1

        # existential: random (r, o, p) patterns, half with a time window
        for _ in range(5):
            lo = rng.choice([None, rng.randint(0, 60)])
            pat = smt.AccessPattern(r=rng.choice(sorted(p.roles)), o=rng.choice(sorted(p.objects)),
                                    p=rng.choice(sorted(p.purposes)), t_from=lo,
                                    t_to=None if lo is None else lo + rng.randint(0, 30))
            res["find_access"] += 1
            w = smt.find_access(p, pat)
            if (w is None) != (engine_find_access(p, pat, "enum") is None) or \
                    (w is not None and not engine.auth(p, w)):
                res["find_access_mismatch"] += 1

        res["dead_policies"] += 1
        if smt.dead_permissions(p) != engine_dead(p, "enum"):
            res["dead_mismatch"] += 1

        if p.sod:
            res["sod_policies"] += 1
            viol = smt.temporal_sod(p)
            if {(v.user, v.roles) for v in viol} != engine_sod(p, "enum"):
                res["sod_mismatch"] += 1
            for v in viol:
                if not set(v.roles) <= engine.act_t(p, v.user, v.t):
                    res["sod_bad_witness"] += 1

        # repair: forbid an (o, p) pair that is currently reachable, keep up to
        # three authorised requests outside the pattern
        if seed % 4 == 0:
            authorised = [q for q in (random_request(p, rng, 100) for _ in range(400))
                          if engine.auth(p, q)]
            if authorised:
                target = authorised[0]
                pat = smt.AccessPattern(o=target.o, p=target.p)
                keep = [q for q in authorised if (q.o, q.p) != (target.o, target.p)][:3]
                res["repairs_attempted"] += 1
                out = smt.repair(p, [pat], keep)
                if out is None:
                    res["repairs_infeasible"] += 1
                    continue
                res["repairs_found"] += 1
                rp = out.policy
                orig = p.temporal_relations()
                shrunk_only = all(
                    all(t in orig[kind][k] for t in instants(rp, "enum") if t in iv)
                    for kind, rel in rp.temporal_relations().items() for k, iv in rel.items())
                if (engine_find_access(rp, pat, "enum") is not None
                        or not all(engine.auth(rp, q) for q in keep) or not shrunk_only):
                    res["repair_unsound"] += 1
    return res


# ---------------------------------------------------------------------------
# Part 2: timing
# ---------------------------------------------------------------------------
def chain_policy(depth: int) -> Policy:
    roles = [f"r{i}" for i in range(depth)]
    A = always()
    return Policy(
        users=frozenset({"u"}), roles=frozenset(roles), objects=frozenset({"o"}),
        labels=frozenset({"L"}), purposes=frozenset({"p"}),
        ua={("u", "r0"): A}, pa={(roles[-1], "o"): A},
        h={(roles[i], roles[i + 1]): A for i in range(depth - 1)},
        rho_u={"u": frozenset({"L"})}, rho_g={"o": frozenset({"L"})},
        rho_s={"o": frozenset({"L"})}, gamma=frozenset({("L", "L")}),
        pi={(roles[-1], "o"): frozenset({"p"})}, delta={"p": frozenset({"o"})},
        sod=frozenset(),
    )


def request_latency(name: str, p: Policy, reqs: list[Request], fixedpoint: bool) -> dict:
    row: dict = {"policy": name}
    se, build = timed(smt.SmtEngine, p)
    row["smt_build_ms"] = build * 1e3
    impls = [("engine", lambda q: engine.auth(p, q)), ("smt_unroll", se.auth)]
    if fixedpoint:
        fe, build = timed(smt.FixedpointEngine, p)
        row["fixedpoint_build_ms"] = build * 1e3
        impls.append(("smt_fixedpoint", fe.auth))
    for label, fn in impls:
        fn(reqs[0])  # warm caches
        lat = []
        for q in reqs:
            _, dt = timed(fn, q)
            lat.append(dt * 1e3)
        row[label] = {"median_ms": statistics.median(lat), "p95_ms": pct(lat, 0.95),
                      "p99_ms": pct(lat, 0.99)}
    return row


def analysis_timing(name: str, p: Policy, enum_ok: bool) -> dict:
    row: dict = {"policy": name}
    for label, fn in (("smt", lambda: (smt.dead_permissions(p), smt.temporal_sod(p))),
                      ("engine_breakpoints", lambda: (engine_dead(p, "breakpoints"),
                                                      engine_sod(p, "breakpoints"))),
                      ("engine_enum", lambda: (engine_dead(p, "enum"), engine_sod(p, "enum")))):
        if label == "engine_enum" and not enum_ok:
            row[label] = None
            continue
        (dead, sod), dt = timed(fn)
        row[label] = {"s": dt, "dead": len(dead), "sod": len(sod)}
    return row


def timing(quick: bool) -> dict:
    out: dict = {"requests": [], "analysis": [], "repair": []}
    rng = random.Random(1)
    n_req = 100 if quick else 300

    scen = build_policy()
    out["requests"].append(request_latency(
        "pharma_hospital", scen, [random_request(scen, rng, 399) for _ in range(n_req)], True))

    sizes = [(10, 0.25), (50, 0.05), (200, 0.0125)] if quick else \
        [(10, 0.25), (50, 0.05), (200, 0.0125), (1000, 0.0025)]
    for n_roles, hd in sizes:
        k = Knobs(n_users=n_roles // 2, n_roles=n_roles, n_objects=n_roles // 2,
                  n_labels=5, n_purposes=5, pa_density=4 / n_roles, h_density=hd,
                  sod_pairs=n_roles // 5)
        p = generate(k, seed=n_roles)
        reqs = [random_request(p, rng, 60) for _ in range(n_req)]
        out["requests"].append(request_latency(f"synthetic |R|={n_roles}", p, reqs, n_roles <= 200))

    for depth in ([10, 50, 200] if quick else [10, 50, 200, 800]):
        p = chain_policy(depth)
        reqs = [Request("u", "r0", "o", "p", "L", rng.randint(0, 100)) for _ in range(n_req)]
        out["requests"].append(request_latency(f"chain depth {depth}", p, reqs, depth <= 200))

    for k in (1, 100, 10_000):
        out["analysis"].append(analysis_timing(f"pharma_hospital, time x{k}",
                                               scale_time(scen, k), enum_ok=k <= 100))
    for n_roles in ([10, 30] if quick else [10, 30, 60]):
        kn = Knobs(n_users=n_roles // 2, n_roles=n_roles, n_objects=n_roles // 2, n_labels=4,
                   n_purposes=4, pa_density=4 / n_roles, h_density=2.5 / n_roles,
                   sod_pairs=n_roles // 3)
        out["analysis"].append(analysis_timing(f"synthetic |R|={n_roles}",
                                               generate(kn, seed=7 + n_roles), enum_ok=True))

    pat = smt.AccessPattern(o="genome", p="research", t_from=200)
    keep = [Request("erin", "analyst", "labresults", "research", "UK", 250)]
    for k in (1, 10_000):
        res, dt = timed(smt.repair, scale_time(scen, k), [pat if k == 1 else
                        smt.AccessPattern(o="genome", p="research", t_from=200 * k)],
                        [replace(keep[0], t=250 * k)])
        out["repair"].append({"policy": f"pharma_hospital, time x{k}", "s": dt,
                              "cost": res.cost if res else None,
                              "edits": [f"{e.edge}: {e.before} -> {e.after}"
                                        for e in res.edits] if res else None})
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    meta = {**machine.describe(), "z3": z3.get_version_string()}
    print(json.dumps(meta, indent=2))

    n_pol, n_req = (60, 20) if args.quick else (200, 30)
    agree, dt = timed(agreement, n_pol, n_req)
    print(f"\n== agreement ({n_pol} random policies, {dt:.1f} s) ==")
    print(json.dumps(agree, indent=2))

    t = timing(args.quick)
    print("\n== per-request latency (ms) ==")
    for row in t["requests"]:
        cells = [f"{k}: med {v['median_ms']:.3f} p95 {v['p95_ms']:.3f}"
                 for k, v in row.items() if isinstance(v, dict)]
        print(f"{row['policy']:<24} build {row['smt_build_ms']:.1f} ms | " + " | ".join(cells))
    print("\n== analysis: dead permissions + temporal SoD (s) ==")
    for row in t["analysis"]:
        cells = [f"{k}: {v['s']:.3f} (dead {v['dead']}, sod {v['sod']})" if v else f"{k}: skipped"
                 for k, v in row.items() if k != "policy"]
        print(f"{row['policy']:<30} " + " | ".join(cells))
    print("\n== repair ==")
    for row in t["repair"]:
        print(f"{row['policy']:<30} {row['s']:.2f} s cost {row['cost']} {row['edits']}")

    RESULTS.mkdir(exist_ok=True)
    out = RESULTS / "compare_smt.json"
    out.write_text(json.dumps({"meta": meta, "agreement": agree, "timing": t,
                               "seeds": {"agreement": list(range(n_pol)), "timing_rng": 1}},
                              indent=2))
    print(f"\nwritten {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

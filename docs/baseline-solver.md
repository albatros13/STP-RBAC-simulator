# Initial naive implementation 

This compares the code in this repository with the plan in
`docs/evaluation-plan.md`. It covers how authorisation decisions are
currently made, what is missing, and what to build next.

**There is no solver.** Nothing in the code imports Z3, and there is no
`smt.py`, `rego.py` or `algorithms.py`. Every decision is made by plain Python
that evaluates the formulas directly.

## How decisions are made now

In `stprbac/engine.py`, each request is checked against six conditions:

| Condition | How it is computed |
|---|---|
| activation | `act_t`: collects the user's role assignments valid at `t`, then expands them through the role hierarchy using `senior_closure`. That function finds the hierarchy edges active at `t` and repeats a closure loop until nothing changes. |
| locus | checks whether the requested location is in `rho_u[u]` |
| assignment | `pa_star_t`: checks whether any role reachable through the hierarchy has a permission on `o` that is valid at `t` |
| spatial | `region_ok`: every governing jurisdiction must admit the location, and at least one storage site must be reachable |
| purpose | `pi_t`: the union of permitted purposes over the inherited permissions |
| minimisation | checks whether `o` is in `delta[p]` |

`auth()` is simply `all(...)` over these six results. `coordinator_prefilter`
and `worker_decision` call the same function and keep only the results that
belong to their phase.

So the current engine checks one concrete request at a time, using fixed policy
values. It cannot answer questions about the policy as a whole, such as "is
there any request that should be denied but gets through?", "where do
separation-of-duty rules conflict?" or "what is the smallest change that fixes
this?". Those questions need the SMT encoding (E3) or the A-series algorithms,
and neither exists yet.

It is also not the fast `auth_indexed` engine the plan describes. It is close to
the slow `auth_naive` baseline: the hierarchy closure is recomputed up to three
times per request, and both phases recompute all six conditions. That isn't a
problem for correctness, but it should be labelled as the naive baseline before
any E2 timings are reported.

## What exists and matches the plan

- `intervals.py`: matches §0.2, including merging of touching intervals and
  binary-search `first_after`.
- `model.py`: the `Policy` fields match Definition 1, and a cyclic role
  hierarchy is rejected.
- `engine.py`: implements `Act_t`, `PA*_t`, `Π_t`, `RegionOK`, `Auth` and the
  two-phase split.
- `diagnose.py`: partly done (see E6 below).
- `scenarios/pharma_hospital.py`: the first E1 scenario. The plan expects it
  under `generators/scenarios/`.
- The federation (`federation/`, `run_federation.py`) is **not in the plan**.
  It is an extra that demonstrates the two-phase enforcement of Corollary 2 at
  runtime.

## What's missing

**§0 Infrastructure**

- `generators/synthetic.py`: a seeded generator with the 11 settings from §0.3,
  building role hierarchies as random acyclic graphs by fixing an order first.
  **Every benchmark depends on this.**
- `tests/`: **there are no tests at all.** The plan says this comes before any
  benchmarking:
  - a Hypothesis test that `auth_naive` and `auth_fast` agree (which needs two
    separate implementations);
  - Proposition 1 (backward compatibility), which needs an `Auth_prev`
    implementation;
  - Theorem 2 (monotonicity), which needs relaxation and tightening generators
    that handle the reversed direction of `rho_g`.

**E1 Expressiveness**

- Two more scenarios, taken from published deployments.
- A `constraints.yaml` per scenario, giving each constraint a verdict.

**E2 Checking performance**

- `algorithms.py`:
  - A1: indexed `auth` (interval tree plus memoised hierarchy closure).
  - A2: separation-of-duty detection with a sweep line. **SoD is currently not
    checked anywhere**, at request time or during analysis.
  - A3: earliest activation (`first_after` exists, but nothing uses it).
  - A4: consistency and dead-permission check (`Π(r,o) ⊄ {p | o ∈ Δ(p)}`).
  - A5.
- `bench/harness.py`: timing harness reporting p50, p95, p99 and p99.9, with
  JSON output.
- `bench/plots.py`.

**E3 Solver scaling**

- `smt.py` with `encode(policy, mode, query)`:
  - a `check` mode where every value is fixed, and a `synthesise` mode where
    interval endpoints are left free;
  - the hierarchy encoded two ways (Fixedpoint/Horn rules and depth-D
    unrolling);
  - four query types: unauthorised access, temporal SoD, dead permission, and
    repair via `z3.Optimize`.
- This also needs `z3-solver` added as a dependency.

**E4 Incrementality**

- `classify_delta`, which labels a policy change as tightening, relaxation or
  mixed under Definition 8.
- An onboarding simulator based on the BraneHub questionnaire.
- Full versus incremental re-verification strategies.

**E5 Fault injection**

- `faults/injectors.py` with defects F1–F6, each returning a mutated policy plus
  an example request that should be denied.
- `Auth_prev`, so F5 (forum shopping) and F6 (hierarchy laundering) can be run
  against both the old and new models.

**E6 Diagnostic usability**

- `diagnose.py` has the failing condition, the enforcement point, the
  responsible policy elements and all failures.
- It lacks `suggested_repairs` (which needs the Z3 repair query) and the raw Z3
  unsat-core presentation used as the comparison.
- The plan says the diagnosis must come from the unsat core. The current one is
  derived from the policy structure. That is defensible, but it is a different
  design from the plan, so either the plan or the paper text needs updating.

## Two problems in the existing code

1. **The coordinator sees the purpose.** `coordinator_prefilter` is documented
   as not reading `q.p`. However, `_phase` calls `evaluate_conjuncts`, which
   evaluates the purpose and minimisation checks too, and then throws those
   results away. On top of that, the coordinator's `/request` endpoint receives
   `p` in the request body, and its `diagnose` call evaluates every condition.
   The verdicts are still correct. But the property that the coordinator never
   learns the purpose, which is the argument for the two-phase design, isn't
   actually demonstrated. Fixing it means evaluating only each phase's own
   conditions and keeping `p` away from the coordinator (for example, sealed
   for the worker).

   *Status:* partly fixed. Each phase now evaluates only its own conditions,
   and a test confirms the coordinator phase never reads `q.p`. The wire
   protocol still sends `p` to the coordinator. See `baseline-solver-test.md`.
2. **SoD is stored but never checked**, as mentioned above.

   *Status:* this matches the paper. SoD is a policy-level property, not a
   condition of `Auth`. What's missing is the A2 analysis, not a runtime
   check.

## Suggested order

Following the plan's own priorities:

1. Tests, plus a separate `auth_naive`, with the current engine kept as the
   reference.
2. The synthetic generator.
3. `algorithms.py`: A1 indexed, A2 SoD, A4 dead permissions.
4. `smt.py`, starting with `check` mode and the unauthorised-access query, then
   synthesis and repair.
5. `Auth_prev`, the fault injectors, then `classify_delta`.

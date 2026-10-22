# STP-RBAC on OPA/Rego

This note describes the policy-as-code implementation of the STP-RBAC
authorisation predicate on Open Policy Agent (OPA). It covers what is encoded,
how, how it was validated, what it costs, and what it cannot do.

Setup used for all numbers: OPA 1.16.2 (Rego v1), Python 3.14.4 (CPython),
Linux 7.0 x86-64.

## 1. Purpose and position in the architecture

The paper's remark in Section 6 says a deployment that needs only ground
request checks should use a policy-as-code engine rather than an SMT solver.
This implementation is that runtime path. It answers one fully specified
request `q = (u, r, o, p, l, t)` at a time, with exactly the semantics of
`Auth_Θ(q)` (Definitions 3–6). It also implements the two-phase split of
Corollary 2, so the coordinator and the workers can each query OPA for their
own conjuncts.

It is not an analysis tool. Existential and optimisation questions (dead
permissions, temporal SoD, repair) stay with the SMT encoding; see
`smt-solver.md`.

## 2. Components

| File | Role |
|---|---|
| `policies/stprbac.rego` (145 lines) | The rules. Policy-independent: no scenario data is hard-coded. |
| `policies/scenarios/pharma_hospital/data.json` | The example scenario as an OPA data document (generated). |
| `stprbac/rego.py` | Policy → OPA data conversion, plus two evaluators: `OpaCli` (local `opa eval`) and `OpaServer` (OPA REST API). Standard library only. |
| `run_opa.py` | Command line: `export`, `demo` (local, temporary server, or `--url`), `serve`. |
| `policies/stprbac_test.rego` | 10 Rego unit tests (`opa test policies/`). |
| `tests/test_rego.py` | Differential tests against the Python reference engine. |

**Separation of rules and data.** The rules are written once. A policy `Θ` is
loaded as the data document `data.policy`, so one OPA instance can be
re-pointed at a new policy at run time through the Data API
(`PUT /v1/data/policy`) without recompiling the rules. This matches the
federation's model, where the coordinator distributes an approved policy to
all nodes.

## 3. Encoding

### 3.1 Data layout

Pair-indexed relations become nested objects, so that Rego can look them up
directly (`P.pa[r][o]`) instead of scanning lists. Validity sets `τ` become
lists of closed integer intervals `[a, b]`.

| Model element | OPA data |
|---|---|
| `R` | `roles: [r, ...]` |
| `UA`, `τ_U` | `ua: {u: {r: [[a,b], ...]}}` |
| `PA`, `τ_P` | `pa: {r: {o: [[a,b], ...]}}` |
| `H`, `τ_H` | `h: {senior: {junior: [[a,b], ...]}}` |
| `ρ_U`, `ρ_G`, `ρ_S` | `rho_u / rho_g / rho_s: {x: [l, ...]}` |
| `Γ` | `gamma: {l: [l', ...]}` (adjacency map) |
| `Π` | `pi: {r: {o: [p, ...]}}` |
| `Δ` | `delta: {p: [o, ...]}` |
| `SoD` | not exported, because it is not a conjunct of `Auth` |

### 3.2 Rules

| Paper | Rego |
|---|---|
| `t ∈ τ(x)` | `active(ivs, t)`: some `[a, b]` in `ivs` with `a ≤ t ≤ b` |
| `H_t` | `h_at_t`: adjacency map of the hierarchy edges active at `input.t` |
| `{r' \| r ⪰_t r'}` | `juniors := graph.reachable(h_at_t, {input.r})` |
| `Act_t(u)` | `act := graph.reachable(h_at_t, {r' \| τ_U(u, r') ∋ t})` |
| (1) activation | `input.r in act` |
| (2) locus | `input.l in P.rho_u[input.u]` |
| (3) assignment `PA*_t` | some `r'' ∈ juniors` with `t ∈ τ_P(r'', o)` |
| (4) spatial `RegionOK` | `every lg in rho_g[o] { lg in gamma[l] }` and `some ls in rho_s[o]; ls in gamma[l]` |
| (5) purpose `Π_t` | some `r'' ∈ juniors` with `t ∈ τ_P(r'', o)` and `p ∈ Π(r'', o)` (same witness as the assignment) |
| (6) minimisation | `input.o in P.delta[input.p]` |

Each conjunct is a separate Boolean rule with `default := false`. A request
that names an unknown user, role, object, purpose or locus therefore evaluates
to `false` rather than "undefined", so OPA's fail-closed behaviour coincides
with the model's.

### 3.3 Entry points (`data.stprbac.authz.*`)

| Rule | Output | Used by |
|---|---|---|
| `decision` | `allow`, all six `conjuncts`, `first_failure` (fixed order, or `null`) | single-node deployments, diagnosis |
| `coordinator` | `passed`, `conjuncts`, `first_failure` for conjuncts 1–4 | coordinator (phase 1) |
| `worker` | the same for conjuncts 5–6 | data-provider worker (phase 2) |
| `batch` | `decision` for each element of `input.requests`, in order | bulk evaluation, testing |

**Purpose confidentiality (Corollary 2).** `coordinator` refers only to
conjuncts 1–4, and Rego evaluates rules on demand. A coordinator query
therefore never reads `input.p`, and the coordinator can send its query
without the purpose at all (`request_to_input(q, with_purpose=False)`). This is
tested in both the Rego suite and the Python suite. In the Python engine the
same property needed an explicit fix (see `baseline-solver-test.md`); in Rego
it follows from lazy evaluation.

**First failure.** `first_failure` scans the fixed conjunct order. JSON
objects are unordered, so the order is kept in a separate array and not
derived from the `conjuncts` object.

## 4. Design points and pitfalls worth reporting

1. **No recursion in Rego.** The role hierarchy closure `⪰_t` is a transitive
   closure. Rego forbids recursive rules, so it cannot be written as the Horn
   rules of Section 6. The implementation instead computes the time-slice `H_t`
   as an adjacency map and calls the built-in `graph.reachable`. This is
   correct because `H` is acyclic and validated on construction. More
   importantly, the slice is taken *before* the closure: hierarchy edges that
   are inactive at `t` cannot be traversed. A static closure would be wrong
   here, because Definition 3 uses only the edges active at `t`.

2. **`graph.reachable` silently drops non-key nodes.** The built-in returns
   only nodes that appear as keys of the graph object. For example,
   `graph.reachable({"a": {"b"}}, {"c"})` returns `[]`, not `["c"]`. A leaf
   role (no juniors) is therefore missing from its own closure unless it is a
   key. The first version of the encoding had this bug: activation and
   assignment failed for every role without juniors, and OPA raised no error.
   The fix exports `R` and keys `h_at_t` on every role. This kind of silent
   semantic gap in a policy language's built-ins is a point worth making in
   the paper: the Rego looked correct and type-checked under `opa check
   --strict`, and only differential testing against the reference engine
   exposed it.

3. **Fused purpose witness.** As in the SMT encoding, purpose and assignment
   must be witnessed by the same junior role `r''`. The `purpose` rule
   re-checks `t ∈ τ_P(r'', o)` for the same `r''` that supplies `p ∈ Π(r'', o)`.
   It does not combine a separately computed `PA*_t` with `Π`.

4. **Jurisdiction does not flow through the hierarchy.** `locus` and `spatial`
   are evaluated against the declared `input.l` only, never against a role in
   the closure (Remark 3, hierarchy laundering).

5. **Rules loaded once, by a single identity.** OPA rejects two modules that
   both define `default allow` in the same package. If the same `.rego` is
   loaded both from disk and through the Policy API (under a different module
   id), the second load fails with a type error. The Python tooling therefore
   always loads rules through `PUT /v1/policies/stprbac` and data through
   `PUT /v1/data/policy`, so a reload replaces them in place.

## 5. Validation

| Check | Scope | Result |
|---|---|---|
| Exhaustive differential test vs `stprbac.engine` (pharma_hospital) | all `U × R × O × P × L` (5·5·6·5·5 = 3,750 tuples) at every interval endpoint, endpoint ±1 and midpoint (12 instants) = **45,000 requests**; compares all six conjuncts and `first_failure` | 0 mismatches |
| Random policies | 20 seeded synthetic policies (`generators.synthetic.random_small`), up to 500 requests each | 0 mismatches |
| Two-phase over REST | every 37th request of the exhaustive set: `coordinator` (sent without `p`) and `worker` vs `engine.coordinator_prefilter` / `worker_decision`, and `decision.allow` vs `engine.auth` | 0 mismatches |
| Policy reload | swap `Θ` on a running server through the Data API; decision changes accordingly | passes |
| Rego unit tests (`opa test`) | the 6 demo cases, hierarchy-edge expiry, phase-4 auditor activation, coordinator without purpose, batch ordering | 10/10 pass |
| Unknown names | unknown role, user, object or locus | always denied, never an error |

The Python engine is itself validated against a naive whole-policy fixpoint
oracle (`tests/test_engine.py`, 12,000 comparisons). This gives a chain of
three independent implementations (naive oracle, engine, Rego) that agree.

## 6. Performance

Per-request latency, 300 random requests per row (`random_request` in
`bench/compare_smt.py`, seed 1). The rows use the same synthetic policies and
chain hierarchies as the SMT benchmark. "REST" is one HTTP round trip per
request to a local `opa run --server`, including Python client overhead.
"Batch" is one call carrying all 300 requests, divided by 300.

| Policy | Python engine, median | OPA REST, median / p95 | OPA REST batch, per request | `opa eval`, median |
|---|---|---|---|---|
| pharma_hospital | 0.012 ms | 0.62 / 0.98 ms | 0.15 ms | 10.7 ms |
| synthetic, \|R\| = 10 | 0.007 ms | 0.64 / 1.32 ms | 0.22 ms | 10.0 ms |
| synthetic, \|R\| = 50 | 0.007 ms | 1.22 / 2.55 ms | 0.76 ms | 13.8 ms |
| synthetic, \|R\| = 200 | 0.014 ms | 2.80 / 4.72 ms | 2.21 ms | 15.8 ms |
| synthetic, \|R\| = 1000 | 0.008 ms | 15.8 / 22.1 ms | 15.5 ms | 46.5 ms |
| chain depth 10 | 0.023 ms | 0.77 / 1.31 ms | 0.26 ms | 10.3 ms |
| chain depth 200 | 0.49 ms | 2.95 / 5.40 ms | 2.00 ms | 14.9 ms |
| chain depth 800 | 1.47 ms | 13.3 / 20.5 ms | 14.0 ms | 32.2 ms |

How to read this:

- **`opa eval` is for testing, not serving.** About 10 ms of every call is
  process start-up and policy compilation. Batch evaluation amortises it.
- **REST meets the E2 budget at realistic scale.** On the scenario and on
  policies up to a few hundred roles, the p95 is a few milliseconds, most of
  it HTTP and JSON overhead (the batch column shows evaluation alone at
  0.15–2 ms).
- **Cost grows with \|R\|, not with the part of the hierarchy below `r`.** This
  is the main weakness of the encoding. `h_at_t` materialises the active
  slice of the *whole* hierarchy (every role is a key, see §4.2) on every
  query, so each request costs `O(|R| + |H|)`. The Python engine only searches
  below the requested role, and its latency is flat in `|R|`. At
  `|R| = 1000` OPA's p95 is 22 ms, which breaks the "few ms p99" falsifier
  of E2. A fix that keeps the semantics is to precompute the static
  reachability set of each role at export time (time-independent, since `H`
  is fixed). The time slice and `graph.reachable` would then run only over the
  roles statically below `r` and the user's assigned roles. This has not been
  implemented or measured yet.

## 7. Limits

- **Ground requests only.** Rego evaluates a fully specified request. It does
  no symbolic reasoning over time, so it cannot certify "for all `t`" or
  "there exists a `t`" except by enumerating instants. That is possible (for
  example over the breakpoints of the piecewise-constancy lemma,
  `lem:breakpoints`, with comprehensions) but has not been implemented.
  Synthesis and repair are outside its scope. This matches the paper's
  positioning (the remark at the end of Section 6, and Section 7): OPA for
  runtime enforcement, SMT for interval reasoning and synthesis.
- **No SoD.** As in the model, SoD is a whole-policy property and not a
  request-time condition, so it is not exported or checked.
- **Diagnosis is shallow.** OPA reports which conjuncts failed and the first
  one. The responsible policy entries (`diagnose.py`) are not reproduced in
  Rego.
- **Not wired into the federation yet.** The coordinator and workers still
  call the Python engine. Swapping in `OpaServer.decide(q, "coordinator")`
  and `decide(q, "worker")` is mechanical, but it has not been done or
  measured end to end.

## 8. Reproduce

```bash
opa test policies/ -v                          # Rego unit tests
python -m unittest tests.test_rego -v          # differential tests (needs opa on PATH)
python run_opa.py demo                         # demo cases via opa eval
python run_opa.py demo --server                # via a temporary OPA REST server
python run_opa.py serve --port 8181            # long-running server with the scenario loaded
```

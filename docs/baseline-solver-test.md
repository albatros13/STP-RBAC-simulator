# Baseline engine: generality test

This report asks whether `stprbac/engine.py` is a general-purpose implementation
of STP-RBAC decision-making, or whether there are scenarios it cannot handle.
Findings come from reading the code against `docs/main.tex` and from small
experiments run against the engine. Sections 1 and 2 have been fixed; see
"Fixes applied" at the end.

**Summary.** For a single request, the engine correctly evaluates the paper's
Definition 6 on any well-formed policy. The six conditions match
`docs/main.tex:336–356`. As a general decision engine it fell short in four
ways:

1. it did not check that its input policy was well formed;
2. it crashed or slowed down badly on deep role hierarchies;
3. several decision questions are outside what it does;
4. some requirements cannot be expressed in the model at all.

## 1. Missing input validation (fixed)

The paper places constraints on a policy that the code never checked. A
malformed policy was quietly accepted and could produce the wrong answer:

| Paper requires | Engine behaviour | Probe result |
|---|---|---|
| `ρ_G(o)` is non-empty | A missing entry made "every governing jurisdiction admits `l`" trivially true, so the object counted as governed by nobody | object with no `rho_g` entry → **authorised** from any locus that reaches its storage |
| `ρ_U`, `ρ_S` are non-empty | A missing entry → always denied | denied, which at least fails safe |
| `Γ` is reflexive | not checked | a policy without `(EU,EU)` silently blocks EU users from EU data |
| `q ∈ U×R×O×P×L×T` | not checked | UA edge to a role absent from `policy.roles` → still **authorised** |
| `SoD` is irreflexive and symmetric | not checked | — |

The `rho_g` case mattered most. The governance check exists to block forum
shopping (Remark 1), but a missing entry turned it into allow-by-default.

## 2. Crashes and slowdowns at scale (fixed)

Measured on a chain-shaped role hierarchy (`r0 > r1 > … > rN`), one `auth`
call:

| Depth | Time per request |
|---|---|
| 100 | 19 ms |
| 200 | 120 ms |
| 400 | 922 ms |
| 800 | **7.0 s** |
| ~1000 | **`RecursionError`** while the policy is being built (recursive DFS in `model._has_cycle`) |

- **Why it was slow:** `senior_closure` repeated a full pass over every
  hierarchy edge until nothing changed, and recomputed everything for every role
  on every call. Each request called it three times, and the two phases plus
  `diagnose` repeated the whole evaluation. Doubling the depth made it about 8×
  slower, so cost grew with the cube of the depth.
- **Wide, flat hierarchies:** with no hierarchy at all, 10,000 roles took
  6.3 ms per request. That alone is above the "a few ms p99" limit in the E2
  falsifier.
- **Smaller issue:** `IntervalSet.__contains__` rebuilt its `starts` list on
  every call, so membership took linear time, not the logarithmic time its
  docstring claims.
- **Related:** `coordinator_prefilter` evaluated all six conditions, including
  the purpose ones, and then discarded them. The coordinator's `diagnose` call
  did the same. Verdicts were correct, but the claim "the coordinator never
  reads `q.p`" was false in the code.

## 3. Decision questions outside the engine (open; planned work)

The engine only answers one fully specified yes/no request. It cannot do the
following:

- **Separation of duty.** A user who holds both conflicting roles at the same
  time still gets authorised. That matches the paper: Auth has no SoD
  condition, and §"Temporal SoD" treats SoD as a property of the whole policy.
  What's missing is the policy-level check (algorithm A2), not a runtime check.
- **Multi-object requests.** The paper defines `MinData(O′, p)` over a set of
  objects. The engine handles one object, so a workflow step that reads several
  datasets needs one request per object, and nothing checks the set as a
  whole.
- **Requests that last over time.** A request happens at a single instant `t`.
  If an access window closes while processing is still running, nothing
  notices.
- **Open questions about the policy:**
  - "can `u` access `o` under any role?"
  - "when is the earliest time access becomes possible?" (algorithm A3)
  - "does any request get through that shouldn't?"
  - dead permissions
  - "what is the smallest change that fixes this?"

  These are existence or optimisation questions, not single-request
  evaluations. They need the A-series algorithms or the SMT encoding (`smt.py`,
  E3), and neither exists yet. See `docs/baseline-solver.md`.

## 4. Limits of the model itself (open; for the paper's limitations section)

The engine can't express these because the paper's model doesn't include them.
Most are what the E1 plan already predicts will fall outside the model:

- **Obligations:** "delete after 30 days".
- **Retroactive consent withdrawal:** objects have no per-data-subject
  granularity.
- **Cardinality limits:** "at most 3 concurrent analysts".
- **Rules about the policy's own structure:**
  - deny rules
  - break-glass emergency exceptions
  - purpose hierarchies ("clinical research" counting as a kind of "research")
- **Derived data:** the worker's output carries no governance labels, and `Γ`
  isn't transitive, so onward transfers of results aren't tracked.
- **Combining datasets:** no rule like "these two datasets must not be joined".
- **Local worker policies:** in the federation, every worker loads the same
  global policy, so a data provider can't add its own stricter local rules.

## Fixes applied

| Issue | Change |
|---|---|
| No validation | `Policy.__post_init__` runs `model._validate` and raises `ValueError` listing every violation of Definition 1: undeclared names in UA/PA/H/ρ/Γ/Π/Δ/SoD; missing or empty `ρ_U`, `ρ_G`, `ρ_S`; non-reflexive `Γ`; `Π` keys outside `PA`; malformed SoD pairs; cycles in `H`. Requests naming unknown entities are now always denied, because a valid policy cannot reference them. |
| Recursion crash | `_has_cycle` uses Kahn's algorithm (iterative). |
| Cubic closure | `senior_closure` replaced by `engine.juniors_t(policy, r, t)`: an iterative search from the requested role over the hierarchy edges active at `t`, using cached indexes `Policy.h_succ` and `Policy.ua_by_user`. `evaluate_conjuncts` computes it at most once per request and shares it between the assignment and purpose conditions. |
| Linear interval membership | `IntervalSet` stores its start points once at construction (not part of equality or hashing). |
| Phases evaluating everything | `evaluate_conjuncts(policy, q, names)` and `diagnose(policy, q, conjuncts)` evaluate only the conditions they are given. `coordinator_prefilter` and the coordinator's `diagnose` now use `engine.COORDINATOR_CONJUNCTS`; the worker uses `engine.WORKER_CONJUNCTS`. A test confirms the coordinator phase never reads `q.p`. |

Not changed: the federation's wire protocol still sends `p` to the coordinator
in the `/request` body, which forwards it to the worker. Hiding `p` from the
coordinator (for example, sealed for the worker) is a protocol change and is
left open.

### Performance after the fixes

Same probes as section 2, averaged over repeated calls:

| Hierarchy | Before | After |
|---|---|---|
| chain depth 100 | 19 ms | 0.31 ms |
| chain depth 200 | 120 ms | 0.53 ms |
| chain depth 400 | 922 ms | 0.84 ms |
| chain depth 800 | 7.0 s | 1.77 ms |
| chain depth 5000 | crash | 12.4 ms |
| flat, 1,000 roles | 0.26 ms | 0.009 ms |
| flat, 10,000 roles | 6.3 ms | 0.009 ms |

Cost now grows linearly with the part of the hierarchy below the requested role
and no longer depends on the total number of roles. A chain 5,000 deep is still
above the E2 budget. That depth is unrealistic, but the plan's A1
`auth_indexed`, which caches the hierarchy closure per time point, is still
needed before reporting E2 numbers. The current engine should be treated as the
improved naive baseline.

### Tests

There is a new `tests/test_engine.py` (standard library only). Run it with
`python -m unittest discover -s tests -t . -v`. All 18 tests pass. They cover:

- `IntervalSet`: normalisation, membership, `first_after`, and equality;
- every validation rule above;
- the six demo-client cases, checking both the verdict and the failing
  condition;
- agreement, condition by condition, with a naive reference oracle that
  reproduces the original whole-policy closure. This runs on 300 seeded random
  policies with 40 requests each (12,000 comparisons). Every condition comes
  out both true and false across the run;
- the two phases combined giving the same result as `Auth` (2,000 random
  requests on the scenario);
- the coordinator phase not reading the purpose;
- a 5,000-deep hierarchy evaluated in under 1 s, and a 5,000-long cycle
  rejected without a crash.

The federation services were not run (FastAPI, uvicorn and httpx are not
installed in `.venv`). Their edits were syntax-checked only.

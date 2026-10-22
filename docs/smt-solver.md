# STP-RBAC on an SMT solver (Z3)

This note describes the SMT implementation of STP-RBAC (`stprbac/smt.py`,
Section 6 of the paper) and the problems found with it. It is written to
support the claims, and the caveats, in the white paper.

Setup: Z3 5.3.1 (`z3-solver` Python bindings), Python 3.14.4 (CPython), Linux
7.0 x86-64. All numbers in §5 come from a short probe on the
`pharma_hospital` scenario. The full benchmark (`bench/compare_smt.py`, even
with `--quick`) was too slow to finish and was stopped. See §6.1.

## 1. Purpose

The Python engine and the Rego encoding (`rego-solver.md`) answer only ground
requests: "is this `q` authorised?". The SMT encoding exists for the questions
they cannot answer, which quantify over time, over requests or over the policy
itself:

- **unauthorised access**: is any request matching a pattern authorised (with
  a witness)?
- **temporal SoD**: does any user ever hold two conflicting roles at the same
  time?
- **dead permissions**: is some `p ∈ Π(r, o)` never usable?
- **repair**: what is the smallest shrinkage of validity windows that removes
  every forbidden access while keeping required requests authorised?

## 2. Encoding

### 2.1 Two modes, one encoding

| Mode | Interval endpoints | Each constituent interval | Paper's complexity claim |
|---|---|---|---|
| `check` | numerals | always present | polynomial |
| `synthesise` | free `Int`s with `a ≤ b` | Boolean `enabled` flag (a repair may drop it) | NP-hard |

In both modes the Boolean structure of the policy (`Γ`, `Π`, `Δ`, `ρ_U`, `ρ_G`,
`ρ_S`) is fixed. Section 6 of the paper introduces Booleans `Γ_{l,l'}`,
`Π_{r,o,p}` and so on as SMT variables; the implementation folds them into
constants (`BoolVal`) when it builds the formula. This is equivalent in check
mode and consistent with the paper's repair query, which also fixes the Boolean
structure. It does mean that **no query can synthesise or repair `Γ`, `Π`, `Δ`
or `ρ`**.

### 2.2 Formulas (quantifier-free linear integer arithmetic)

- `live_x(t) ↔ ⋁_j (a_{x,j} ≤ t ≤ b_{x,j})`, conjoined with `enabled_{x,j}` in
  synthesise mode.
- **Hierarchy closure `Sen_{r,r'}(t)`**, two variants:
  - *unrolled* (default, both modes). `H` is acyclic, so unrolling to the
    longest path is the same as one pass in topological order:
    `Sen(r, x) = ⋁_{(y,x) ∈ H} Sen(r, y) ∧ live_{(y,x)}(t)`. Only roles that are
    statically reachable from `r` get a term. This is linear in the reachable
    sub-DAG, not `D` times the whole hierarchy as "unroll `D` times" in the
    paper suggests.
  - *Horn rules* on Z3's Fixedpoint engine (Spacer), as written in the paper:
    relations `sen(r, r', t)`, `act(u, r, t)` and `grant(r, o, p, t)` over
    integer-coded entities. Check mode only, because the rules need numeral
    endpoints.
- **Spatial**: `RegionOK` exactly as in the paper (universal over `ρ_G`,
  existential over `ρ_S`). It is ground and simplifies to `true` or `false`.
- **Purpose fused with assignment**: the same junior role `r''` must supply
  both the live permission and `p ∈ Π(r'', o)`, as Section 6 requires.

### 2.3 Queries

| Query | Function | How |
|---|---|---|
| single request | `SmtEngine.auth`, `.evaluate_conjuncts` | persistent solver; `push`, assert `t = q.t` and the formula, `check`, `pop` |
| explanation | `SmtEngine.unsat_core` | `assert_and_track` per conjunct, raw unsat core |
| unauthorised access | `find_access(policy, pattern)` | one selector Boolean per concrete candidate `(u, r, o, p, l)`; `t` is free |
| temporal SoD | `temporal_sod` | `activation(u, r1, t) ∧ activation(u, r2, t)` per user and SoD pair |
| dead permissions | `dead_permissions` | `find_access(r, o, p)` unsatisfiable, for each `(r, o) ∈ PA` and `p ∈ Π(r, o)` |
| repair | `repair(policy, forbidden, required)` | `z3.Optimize`, synthesise mode, minimise total time points removed |

**Safety without quantifiers.** "No `t` in `[lo, hi]` authorises the pattern"
is universally quantified. The encoding keeps it quantifier-free by a
breakpoint argument that generalises the paper's piecewise-constancy lemma
(`lem:breakpoints`) to symbolic endpoints. `Auth` is a positive combination of
`a ≤ t ≤ b` atoms, so the set of times where it holds is a finite union of
intervals. Each of those intervals starts at `lo` or at some window's lower
endpoint `a`. Asserting `¬Auth` at exactly those candidate instants is
therefore exact. In synthesise mode the candidate instants are themselves
variables (`a_{x,j}`), so the safety constraints stay linear.

## 3. What was validated

| Check | Result |
|---|---|
| `SmtEngine.evaluate_conjuncts` vs `stprbac.engine`, 100 random scenario requests | 0 mismatches |
| `FixedpointEngine.auth` vs `engine.auth`, same requests | 0 mismatches |
| `dead_permissions`, `temporal_sod` on the scenario vs the engine's breakpoint baseline | same result (none of either) |
| repair on the scenario: forbid `genome`/`research` from `t = 200`, keep `erin`/`analyst`/`labresults`/`research`/`UK`/`t = 250` | `PA(analyst, genome)`: `[100,299] → [100,199]`, cost 100 time points. This is the minimum. |

`bench/compare_smt.py` also contains a wider agreement sweep over random
policies (requests, `find_access`, dead permissions, SoD, and the soundness of
repairs against the engine). It did not finish (§6.1), so this note claims no
results from it.

## 4. Problems

### 4.1 Repair cannot split a window (incompleteness, over-repair)

Each constituent interval may only be narrowed (`[a, b] → [a', b']` with
`a ≤ a' ≤ b' ≤ b`) or dropped. It can never be split in two. Some minimal
repairs are therefore out of reach.

Reproduced on a one-user, one-role policy with `τ_U = τ_P = [0, 100]`:

| Forbid | Keep authorised | Minimal repair | `repair()` returns |
|---|---|---|---|
| `t ∈ [40, 60]` | `t = 10` and `t = 90` | `τ_P = [0,39] ∪ [61,100]`, cost 21 | **`None`** ("no shrink-only repair exists") |
| `t ∈ [40, 60]` | `t = 10` | the same, cost 21 | `τ_P = [0, 39]`, **cost 61** |

So `repair` is not complete for the problem as stated in the paper ("minimise
total window shrinkage"). A `None` result does not prove that no repair
exists, and the reported optimum can be about 3× the true one. Fix: give each
window `k` sub-windows (or one optional "hole" `[c, d]`) in synthesise mode.
This adds variables and makes the hard problem harder.

A smaller quirk of the cost function: dropping a window costs `b − a + 1`, but
shrinking it to a single point `[x, x]` costs `b − a`. If a one-point
remnant happens to be safe, the optimiser prefers it to deleting the window,
which leaves odd one-instant permissions in the repaired policy.

### 4.2 The solver only searches over time; everything else is enumerated in Python

`candidates()` expands the pattern over `U × O × P × L × R` in Python, drops the
tuples whose ground part (locus, spatial, minimisation) is false, and builds a
separate `Auth` formula for each remaining tuple. The solver sees a big
disjunction of selectors, and its only real unknown is `t` (plus the endpoints
in synthesise mode).

This matters for the paper:

- **Formula size** grows with `|U|·|R|·|O|·|P|·|L|`, before Z3 does any work.
  A query with no fixed fields pays the full product.
- **The SMT solver is not the reason the analyses are decidable.** The same
  questions are answered exactly by evaluating the ground engine at the
  breakpoint instants (Lemma `lem:breakpoints`; `engine_find_access(...,
  "breakpoints")` in the benchmark). On the scenario that baseline is about
  55× faster (§5).
- **`dead_permissions` re-encodes from scratch** for every `(r, o, p)`: one
  new solver and a full candidate expansion per entry, with no reuse between
  queries.

The honest claim is therefore narrower than "SMT for analysis". Check-mode
analysis does not need a solver. The solver earns its cost only for
**synthesis and repair**, where endpoints are unknowns. This sharpens the
paper's own remark at the end of Section 6.

### 4.3 Synthesis and repair do not scale

`repair` uses `z3.Optimize` over free endpoints, `enabled` flags and a sum
objective. That is the NP-hard part, and it shows: **5.7 s on the 5-role,
6-object scenario** with one forbidden pattern and one required request. The
full benchmark adds larger policies, repairs inside the agreement sweep and a
×10,000 time-scaled scenario, and it did not finish. `repair` takes a
`timeout_ms` and raises `TimeoutError` on `unknown`. Above toy sizes it
should be treated as a best-effort tool, not a decision procedure.

### 4.4 Per-request decisions are 50–100× slower than the direct engine

On the scenario, `SmtEngine.auth` has a median of 0.64 ms (p95 0.87 ms).
The Python engine takes 0.01 ms. `evaluate_conjuncts` costs one `check()` per
conjunct, so diagnosis is about 6× a single decision (0.99 ms median). This
is inside the E2 budget for small policies, but it gains nothing. On ground
requests every formula is already constant-foldable, so the solver is pure
overhead. Use the engine or OPA for runtime decisions.

### 4.5 The Fixedpoint (Horn) engine has a heavy tail

The median is 0.47 ms, but the p95 is 3.40 ms (7× the median) on the same
requests. Spacer's run time varies with the query. Combined with check-mode
only and integer-coding of entities, the Horn variant is a faithful
rendering of the paper's rules rather than a practical engine. The unrolled
encoding is the one to use.

### 4.6 Robustness gaps

- `FixedpointEngine.auth` raises `KeyError` on a request naming an unknown
  role, user, object or purpose (entities are integer-coded via dict lookup).
  The engine, `SmtEngine` and OPA all deny such requests. The bug is
  reproduced with role `"nurse"`.
- `SmtEngine.unsat_core` returns *a* core, not the set of failing conjuncts
  and not necessarily the first failure. Example: `carol/analyst/report/
  reporting/US/t=150` fails both `assignment` and `spatial`, but the core is
  `['assignment']`. That is fine for E6 as the "raw solver baseline", but it
  must not be presented as a complete diagnosis.

### 4.7 Deviations from the paper's text

| Paper (Section 6) | Implementation | Consequence |
|---|---|---|
| `Γ`, `Π`, `Δ`, `ρ` as Boolean SMT variables | folded into constants | no structural synthesis or repair (§2.1) |
| unroll the Horn rules `D` times | one topological pass over the statically reachable sub-DAG | equivalent and smaller; describe it this way |
| "Dead permission: `¬∃ t, l : Auth_{u,r,o,p,l}(t)`" | also quantifies over `u` (any user) | the code's reading is the intended one; the formula in the paper should quantify `u` explicitly |
| repair "minimises total window shrinkage" | shrink-only, no splitting | incomplete (§4.1) |

## 5. Measurements (pharma_hospital, probe)

100 random requests (`random_request`, seed 1, `t ∈ [−5, 399]`).

| Operation | Time |
|---|---|
| build `SmtEngine` / `FixedpointEngine` | 5.2 ms / 5.6 ms |
| `engine.auth` (reference) | median 0.01 ms, p95 0.01 ms |
| `SmtEngine.auth` | median 0.64 ms, p95 0.87 ms |
| `SmtEngine.evaluate_conjuncts` | median 0.99 ms, p95 1.27 ms |
| `FixedpointEngine.auth` | median 0.47 ms, p95 3.40 ms |
| `dead_permissions`: SMT vs engine at breakpoints | 0.22 s vs 0.004 s (both: none) |
| `temporal_sod`: SMT vs engine at breakpoints | < 0.01 s vs 0.0001 s (both: none) |
| `repair` (one pattern, one required request) | 5.73 s, cost 100 |

## 6. Status of the benchmark

### 6.1 `bench/compare_smt.py` is too slow to run

Even `--quick` (60 random policies × 20 requests, plus `find_access`, dead
permissions, SoD and a repair on every 4th policy, then a timing sweep up to
`|R| = 200`, chains to depth 200 and repairs on the ×10,000 scaled scenario)
did not finish and was stopped. The script prints only at the end of each
part, and its stdout was buffered, so we do not know which stage dominates.
The most likely candidates are the repairs (§4.3) and the per-entry
re-encoding in `dead_permissions` (§4.2).

To get reportable numbers:

- run with `python -u` and add a per-stage time limit (`repair(...,
  timeout_ms=...)` already exists and is not used by the benchmark);
- report repair separately, as a function of policy size, with timeouts
  counted as such;
- shrink the agreement sweep, or run it without the repair stage.

### 6.2 What can be claimed today

- The encoding is correct on the scenario for single requests, both
  closure variants, dead permissions, SoD and one repair instance, against an
  independently validated engine.
- Check-mode analysis is decidable without a solver, and is faster that way
  (§4.2).
- Repair works on toy instances, but it is incomplete (no window splitting)
  and expensive (seconds at 5 roles).
- No scaling claims for the SMT path can be made yet.

## 7. Reproduce

```bash
python -m unittest discover -s tests -t . -v    # engine tests (the SMT path has no unit tests of its own)
python -u -m bench.compare_smt --quick          # full comparison; slow, see §6.1
```

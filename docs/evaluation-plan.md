# What to build for the evaluation section

This is the engineering spec behind Section 7 of the paper. Each experiment
below states what to implement, what to measure, what to compare against, and
what result would make the corresponding claim in the paper false. Build in the
order E2, E1, E5, E4, E3, E6: E2 gives you the reference implementation that
everything else runs on, and E6 needs human participants so it should be
scheduled last.

---

## 0. Reference implementation (prerequisite for everything)

### 0.1 Repository layout

```
stp-rbac/
  stprbac/
    model.py          # Policy dataclass, exactly Definition 1
    intervals.py      # IntervalSet: union, intersection, membership, endpoints
    engine.py         # Act_t, PA*_t, Pi_t, Auth  (Definitions 3, 6)
    algorithms.py     # A1-A5
    smt.py            # Z3 encoding, both modes (Section 6)
    rego.py           # Rego emitter for the runtime path
    diagnose.py       # denial -> failing conjunct + responsible element
  generators/
    synthetic.py      # parameterised policy generator (see 0.3)
    scenarios/        # hand-encoded real scenarios for E1
  faults/
    injectors.py      # the six defect classes for E5
  bench/
    harness.py        # timing harness, JSON output
    plots.py
  tests/
```

### 0.2 Core data model

Implement `Policy` as a frozen dataclass mirroring Definition 1 field for
field, with the same names. Do not "simplify" during implementation; the value
of a formal model is lost the moment the code and the paper diverge.

```python
@dataclass(frozen=True)
class Policy:
    users: frozenset[str]
    roles: frozenset[str]
    objects: frozenset[str]
    labels: frozenset[str]          # L
    purposes: frozenset[str]        # P
    ua: dict[tuple[str, str], IntervalSet]      # UA with tau_U
    pa: dict[tuple[str, str], IntervalSet]      # PA with tau_P
    h:  dict[tuple[str, str], IntervalSet]      # H  with tau_H, senior -> junior
    rho_u: dict[str, frozenset[str]]            # user  -> admissible loci
    rho_g: dict[str, frozenset[str]]            # object -> GOVERNING regimes
    rho_s: dict[str, frozenset[str]]            # object -> STORAGE sites
    gamma: frozenset[tuple[str, str]]           # (requester_locus, data_label)
    pi: dict[tuple[str, str], frozenset[str]]   # (r,o) -> purposes
    delta: dict[str, frozenset[str]]            # purpose -> admissible objects
    sod: frozenset[frozenset[str]]              # unordered conflicting pairs
```

`IntervalSet` must be a normalised, sorted list of disjoint closed integer
intervals. Normalise on construction (merge touching and overlapping intervals);
almost every bug in this kind of code comes from un-normalised interval lists.
Required operations: `__contains__(t)`, `intersect`, `union`, `is_empty`,
`endpoints()`, `first_after(t)` (binary search, needed by A3).

### 0.3 Synthetic policy generator

One generator with independently varying knobs, so that E2 and E3 can isolate
which dimension drives cost:

| Knob | Range to sweep | Notes |
|---|---|---|
| `n_roles` | 10 … 10 000 (log steps) | |
| `n_objects` | 10 … 10 000 | |
| `n_users` | 10 … 10 000 | |
| `pa_density` | 0.001 … 0.1 | fraction of R x O assigned |
| `hierarchy_depth` | 0, 1, 2, 4, 8 | 0 means H empty |
| `hierarchy_branching` | 2, 4 | |
| `intervals_per_edge` (m) | 1, 2, 4, 8, 16 | drives M |
| `n_labels` | 3, 10, 30 | |
| `gamma_density` | 0.1 … 1.0 | |
| `n_purposes` | 3 … 50 | |
| `sod_pairs` | 0 … 0.05 * |R|^2 | |

Seed every generator run and record the seed in the result JSON. Generate
hierarchies as random DAGs by sampling a topological order first, which
guarantees acyclicity without a rejection loop.

### 0.4 Correctness harness (do this before any benchmarking)

Three checks, all as property-based tests (Hypothesis):

1. **Reference oracle agreement.** Write a deliberately naive `auth_naive` that
   materialises `Act_t`, `PA*_t`, `Pi_t` by brute-force closure with no
   indexing, and assert `auth_naive == auth_fast` over random policies and
   random requests. This is the only defence against an optimised engine that
   is fast and wrong.
2. **Conservative extension (Proposition 1).** Generate policies satisfying the
   restriction in Proposition 1, and assert the STP-RBAC verdict equals a
   direct implementation of the earlier paper's `Auth_prev`. If this test
   fails, either the proof or the code is wrong, and the paper's backward
   compatibility claim collapses.
3. **Monotonicity (Theorem 2).** Generate a random `Theta`, apply a random
   relaxation under Definition 8 (remember the reversal on `rho_g`: relaxation
   *removes* governing labels), and assert
   `auth(Theta, q) implies auth(Theta', q)` over random `q`. Then apply a
   random *tightening* and assert the converse fails at least sometimes, so the
   test is not vacuously passing.

Test 3 doubles as a check that your relaxation generator is correct, which E4
depends on.

---

## E1: Expressiveness

**Build.** A scenario encoder plus a constraint checklist.

1. Hand-encode three scenarios as `Policy` instances in
   `generators/scenarios/`:
   - `pharma_hospital.py`: the running scenario from the compliance paper
     (5 roles, 6 objects, 5 purposes, 4 phases, 5 jurisdictions). You already
     have the full `PA`, `tau`, `Gamma`, `Pi`, `Delta` tables there, so this is
     transcription, not design.
   - Two further scenarios from published federated healthcare deployments.
     Pick ones whose access policies are actually stated in the paper, not
     inferred; if the policy is not in the paper, the scenario is not usable.
2. For each scenario, produce `constraints.yaml` listing every access
   constraint stated in the source text as a separate line item, with a verdict
   field: `expressible | expressible_with_workaround | not_expressible`, plus a
   free-text justification.

**Measure.** Fraction of constraints in each category, per scenario, plus a
taxonomy of the residue.

**Expected residue (state this as a prediction before you run it, so the result
is falsifiable).** Obligations ("must delete after 30 days"), consent
revocation with retroactive effect, and cardinality constraints ("at most 3
concurrent analysts") should land outside the model. If something you predicted
would be expressible turns out not to be, that is a model defect and belongs in
the limitations section, not in a workaround column.

**Falsifier.** If more than roughly a quarter of stated constraints need
workarounds, the expressiveness claim does not hold and the model needs
extension before the paper is submittable.

---

## E2: Checking performance

**Build.** `bench/harness.py` timing A1, A2, A4 against a naive baseline.

- **A1 (authorisation query).** Two implementations: `auth_naive` (scan all of
  `PA`, recompute closure per query) and `auth_indexed` (interval tree +
  per-cell memoised `succeq_t`). Time 10^5 random requests per policy
  configuration. Report median, p95, p99, and p99.9 separately. Median alone is
  not enough here: the coordinator sits on the request path, so the tail is the
  number that decides whether this is deployable.
- **A2 (SoD detection).** Sweep-line implementation versus the nested
  `PA x PA` loop from the earlier draft. Note in the write-up that the baseline
  also computes the wrong predicate (it does not quantify over users), so this
  comparison is about the algorithmic shape, not a like-for-like race.
- **A4 (consistency).** Include the dead-permission check
  `Pi(r,o) subset {p | o in Delta(p)}`. Report how many dead permissions the
  hand-encoded E1 scenarios contain. Finding some in a policy that a human
  wrote carefully is a genuinely useful result and is cheap to obtain.

**Measure.** Wall-clock as a function of each knob in 0.3, holding others
fixed. Fit the observed exponent and compare to the bound in Table 2. State
the machine, Python version, and whether PyPy or CPython.

**Falsifier.** If A1 p99 exceeds a few milliseconds at realistic scale
(hundreds of roles, thousands of objects), the two-phase architecture of
Corollary 2 is not viable at the coordinator and the paper must say so.

---

## E3: Solver scaling

**Build.** `stprbac/smt.py` emitting the encoding of Section 6, with a mode
flag.

```python
def encode(policy, mode: Literal["check", "synthesise"], query: Query) -> z3.Solver
```

In `check` mode, every interval endpoint is a `z3.IntVal` and every Boolean is
`z3.BoolVal`; the formula is ground. In `synthesise` mode, endpoints are
`z3.Int` with only `a <= b` asserted. Implement the hierarchy closure both ways
(Z3 `Fixedpoint` with the Horn rules, and depth-`D` unrolling) and compare;
unrolling usually wins when everything else is ground, and you should report
which you used.

Implement the four query classes from Section 6: unauthorised access, temporal
SoD, dead permission, and repair. For repair, use `z3.Optimize` with the
objective `minimise sum of (b_x - a_x) reductions`.

**Measure.** Solver wall-clock and (for synthesis) whether the model is found
within a 300 s timeout, as policy size grows. Plot the two modes on the same
axes.

**The hypothesis under test** is that the curves separate visibly: checking
should look polynomial, synthesis should show a cliff. If they do not separate,
either the encoding is leaking free variables into check mode, or the synthesis
instances are too easy, and you should build harder ones by adding many
forbidden-overlap constraints.

---

## E4: Incrementality

This is the experiment that measures whether Corollary 2 is worth anything, and
it is the one most likely to produce an uncomfortable answer. Design it so the
uncomfortable answer is reportable.

**Build.**

1. `classify_delta(theta_old, theta_new) -> "tightening" | "relaxation" | "mixed"`
   implementing Definition 8 componentwise. Get the `rho_g` reversal right;
   a delta that adds a governing regime is a *tightening*.
2. An onboarding simulator producing realistic delta sequences: a new
   participant joins with their own datasets, jurisdictions, and constraints.
   Derive the delta shapes from the BraneHub onboarding questionnaire fields
   rather than inventing them, so the distribution is defensible.
3. Two verification strategies: `full` (re-verify everything on every delta) and
   `incremental` (skip verification on pure tightenings, verify only the
   difference on relaxations, re-verify fully on mixed deltas).

**Measure.** Over a few hundred simulated onboarding sequences: the fraction of
deltas in each class, solver invocations saved, and total wall-clock saved.

**Report honestly.** If most real onboarding events turn out to be relaxations
or mixed, Corollary 2 is still sound but operationally uninteresting, and the
paper should say exactly that rather than quietly dropping the experiment. A
negative result here is publishable and useful; a missing one is not.

---

## E5: Fault injection

**Build.** `faults/injectors.py` with six injectors, each taking a clean policy
and returning a mutated policy plus a ground-truth witness request that should
be denied but is not.

| Defect | Injection |
|---|---|
| F1 Expired window still granting | Extend one `tau_P` interval past the project phase boundary |
| F2 Illegal cross-border grant | Add a `Gamma` edge with no adequacy basis, or remove a `rho_g` label |
| F3 Purpose creep | Add a purpose to `Pi(r,o)` not justified by the role's function |
| F4 Minimisation violation | Add an object to `Delta(p)` that `p` does not require |
| F5 Forum shopping (Remark 1) | Give an object two `rho_g` labels, one adequate and one not, and check under the old single-existential rule |
| F6 Hierarchy laundering (Remark 3) | Make a senior role in a non-adequate jurisdiction inherit from a junior role in an adequate one |

**Measure.** Detection rate and time to detection for each defect class, using
the A-series algorithms and the SMT queries.

**Run F5 and F6 twice**, once against the corrected model and once against a
faithful implementation of the earlier paper's `Auth_prev`. The claim in the
paper is that the corrected model catches these and the earlier one does not.
Implement `Auth_prev` for real rather than reasoning about it on paper: this is
a two-line difference in quantifier structure and it is exactly the kind of
thing that is easy to get backwards.

**Falsifier.** If the corrected model does not in fact catch F5 or F6, Remarks
1 and 3 are wrong and must be withdrawn.

---

## E6: Diagnostic usability

**Build.** `stprbac/diagnose.py` returning, for a denied request, a structured
record:

```python
@dataclass
class Denial:
    failing_conjunct: Literal["activation","locus","assignment","spatial","purpose","minimisation"]
    responsible_elements: list[PolicyElement]   # the specific tau, Gamma, Pi or Delta entries
    enforcement_point: Literal["coordinator","worker"]   # from Corollary 2
    suggested_repairs: list[PolicyEdit]         # from the Z3 repair query
```

Because `Auth` is a conjunction of six named conjuncts, a denial always has an
identifiable cause; evaluate conjuncts in the fixed order above and report the
first failure, plus all failures if the caller asks. Render two presentations:
a structured one derived from this record, and a raw Z3 unsat core, as the
baseline.

**Measure.** With 8 to 12 participants split between data stewards and workflow
authors, present 6 to 8 denial cases per participant, counterbalanced between
presentations. Record: whether they identify the responsible policy element,
whether their proposed fix is correct (check it by applying the edit and
re-running `Auth`), and time to answer.

**Keep the language model out of the reasoning path.** It may render the
structured record into prose, but the diagnosis itself must come from the unsat
core. If a reviewer can ask "did the LLM invent this explanation", the
experiment has not shown what you want it to show.

---

## Reporting checklist

Before the section is done, confirm each of these is in the write-up:

- [ ] Machine spec, solver version, Python implementation, all generator seeds.
- [ ] For every experiment: the baseline it is compared against.
- [ ] For every claim: the observation that would have falsified it.
- [ ] Which experiments are complete and which are not, stated in the paper's
      conclusion rather than left ambiguous.
- [ ] Artifact: generators, scenarios, and harness released alongside BraneHub,
      so the synthetic results are reproducible without the private scenarios.

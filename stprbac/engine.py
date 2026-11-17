"""The STP-RBAC authorisation engine: Act_t, PA*_t, Pi_t, RegionOK, Auth.

Implements Definitions 3-6 of the paper and the two-phase split of
Corollary 2 (soundness and completeness of two-phase enforcement). Auth is a
conjunction of six named conjuncts, evaluated in the fixed order

    activation, locus, effective-assignment, spatial, purpose, minimisation

so that a denial always has an identifiable first cause (used by diagnose.py).

The two-phase split partitions those conjuncts by whether they depend on the
requested purpose ``p``:

  * coordinator prefilter  G^ST(t, l): activation, locus, effective assignment,
    spatial  -- purpose-INDEPENDENT, computed without knowledge of p;
  * worker decision:       purpose, minimisation -- purpose-DEPENDENT.

Conjunction is associative, so the composite equals Auth exactly.
"""
from __future__ import annotations

from dataclasses import dataclass

from .model import Policy, Request

CONJUNCTS = (
    "activation",
    "locus",
    "assignment",
    "spatial",
    "purpose",
    "minimisation",
)

# Which node observes each conjunct (Corollary 2).
ENFORCEMENT_POINT = {
    "activation": "coordinator",
    "locus": "coordinator",
    "assignment": "coordinator",
    "spatial": "coordinator",
    "purpose": "worker",
    "minimisation": "worker",
}
COORDINATOR_CONJUNCTS = tuple(c for c in CONJUNCTS if ENFORCEMENT_POINT[c] == "coordinator")
WORKER_CONJUNCTS = tuple(c for c in CONJUNCTS if ENFORCEMENT_POINT[c] == "worker")


# ---------------------------------------------------------------------------
# Time-indexed derived relations (Definitions 3-4)
# ---------------------------------------------------------------------------
def juniors_t(policy: Policy, r: str, t: int) -> set[str]:
    """{ r' | r >=_t r' }: roles reachable from r over H-edges active at t.

    Reflexive and transitive. Computed on demand from r alone by an iterative
    graph search, so the cost is bounded by the part of H below r rather than
    by the whole policy.

    Permissions flow upward, membership downward; jurisdiction does NOT flow
    (that is checked against the request's declared locus, never an
    intermediate role -- see Remark 3, hierarchy laundering).
    """
    seen = {r}
    stack = [r]
    succ = policy.h_succ
    while stack:
        s = stack.pop()
        for j, iv in succ.get(s, ()):
            if j not in seen and t in iv:
                seen.add(j)
                stack.append(j)
    return seen


def act_t(policy: Policy, u: str, t: int) -> set[str]:
    """Activation closure Act_t(u): roles u can act in at time t."""
    out: set[str] = set()
    for rprime, iv in policy.ua_by_user.get(u, ()):
        # if rprime is already in out, everything below it is too
        if rprime not in out and t in iv:
            out |= juniors_t(policy, rprime, t)
    return out


def pa_star_t(policy: Policy, r: str, o: str, t: int) -> bool:
    """(r, o) in PA*_t: r inherits an active permission on o at time t."""
    return _pa_star(policy, juniors_t(policy, r, t), o, t)


def pi_t(policy: Policy, r: str, o: str, t: int) -> frozenset[str]:
    """Effective purpose set Pi_t(r, o): union of Pi over inherited assignments."""
    return _pi(policy, juniors_t(policy, r, t), o, t)


def _pa_star(policy: Policy, juniors: set[str], o: str, t: int) -> bool:
    return any(t in policy.tau_p(rprime, o) for rprime in juniors)


def _pi(policy: Policy, juniors: set[str], o: str, t: int) -> frozenset[str]:
    out: set[str] = set()
    for rprime in juniors:
        if t in policy.tau_p(rprime, o):
            out |= policy.pi_of(rprime, o)
    return frozenset(out)


# ---------------------------------------------------------------------------
# Spatial predicate (Definition 5)
# ---------------------------------------------------------------------------
def region_ok(policy: Policy, l: str, o: str) -> bool:
    """RegionOK(l, o): every governing regime permits AND some replica reachable.

        (forall l_g in rho_G(o) : (l, l_g) in Gamma)
      & (exists l_s in rho_S(o) : (l, l_s) in Gamma)

    The universal over governance is what closes the forum-shopping hole of
    Remark 1: an object with any non-adequate governing regime is inaccessible
    regardless of where its replicas sit.
    """
    governing = policy.rho_g.get(o, frozenset())
    storage = policy.rho_s.get(o, frozenset())
    every_governor_permits = all((l, lg) in policy.gamma for lg in governing)
    some_replica_reachable = any((l, ls) in policy.gamma for ls in storage)
    return every_governor_permits and some_replica_reachable


def witness_sites(policy: Policy, l: str, o: str) -> frozenset[str]:
    """{ l_s in rho_S(o) | (l, l_s) in Gamma }: the storage sites of o that
    witness the existential clause of RegionOK for locus l.

    Assumption T4 (faithful routing) requires an admitted request to be
    executed at one of these sites, and nowhere else.
    """
    return frozenset(ls for ls in policy.rho_s.get(o, frozenset())
                     if (l, ls) in policy.gamma)


# ---------------------------------------------------------------------------
# Per-conjunct evaluation and the full predicate (Definition 6)
# ---------------------------------------------------------------------------
def evaluate_conjuncts(policy: Policy, q: Request,
                       names: tuple[str, ...] = CONJUNCTS) -> dict[str, bool]:
    """Evaluate the named conjuncts of Auth for request q (default: all six).

    Only the requested conjuncts are computed, so a phase never reads request
    fields that belong to the other phase (the coordinator never reads q.p).
    """
    juniors: set[str] | None = None

    def below_r() -> set[str]:
        # shared by the assignment and purpose conjuncts; computed at most once
        nonlocal juniors
        if juniors is None:
            juniors = juniors_t(policy, q.r, q.t)
        return juniors

    checks = {
        "activation": lambda: q.r in act_t(policy, q.u, q.t),
        "locus": lambda: q.l in policy.rho_u.get(q.u, frozenset()),
        "assignment": lambda: _pa_star(policy, below_r(), q.o, q.t),
        "spatial": lambda: region_ok(policy, q.l, q.o),
        "purpose": lambda: q.p in _pi(policy, below_r(), q.o, q.t),
        "minimisation": lambda: q.o in policy.delta_of(q.p),
    }
    return {n: checks[n]() for n in CONJUNCTS if n in names}


def auth(policy: Policy, q: Request) -> bool:
    """Auth_Theta(q): the request is authorised iff all six conjuncts hold."""
    return all(evaluate_conjuncts(policy, q).values())


# ---------------------------------------------------------------------------
# Two-phase enforcement (Corollary 2)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PhaseResult:
    passed: bool
    conjuncts: dict[str, bool]          # only the conjuncts this phase owns
    first_failure: str | None           # first failing conjunct, in fixed order


def evaluate_phase(policy: Policy, q: Request,
                   names: tuple[str, ...] = CONJUNCTS) -> PhaseResult:
    """Evaluate the named conjuncts as one phase (default: all six, i.e. Auth)."""
    owned = evaluate_conjuncts(policy, q, names)
    first = next((n for n in CONJUNCTS if n in owned and not owned[n]), None)
    return PhaseResult(passed=all(owned.values()), conjuncts=owned, first_failure=first)


def coordinator_prefilter(policy: Policy, q: Request) -> PhaseResult:
    """Purpose-independent phase evaluated at the coordinator.

    Note ``q.p`` is not read by any conjunct here: the coordinator need not be
    told why a workflow step wants an object.
    """
    return evaluate_phase(policy, q, COORDINATOR_CONJUNCTS)


def worker_decision(policy: Policy, q: Request) -> PhaseResult:
    """Purpose-dependent phase evaluated at the data-provider worker."""
    return evaluate_phase(policy, q, WORKER_CONJUNCTS)

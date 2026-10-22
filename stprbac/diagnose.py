"""Denial diagnosis: map a denied request to its failing conjunct and cause.

Because Auth is a conjunction of six named conjuncts (engine.CONJUNCTS), a
denial always has an identifiable cause. We evaluate conjuncts in the fixed
order and report the first failure, the responsible policy elements, and the
enforcement point (coordinator vs worker) that observed it -- the structured
record behind experiment E6.

The diagnosis is derived structurally from the policy, never from a language
model; prose rendering is a presentation concern only.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import engine
from .model import Policy, Request


@dataclass
class Denial:
    failing_conjunct: str                 # one of engine.CONJUNCTS
    enforcement_point: str                # "coordinator" | "worker"
    responsible_elements: list[str] = field(default_factory=list)
    all_failures: list[str] = field(default_factory=list)
    message: str = ""


_HUMAN = {
    "activation": "the role is not active for this user at this time",
    "locus": "the user may not operate from this jurisdiction",
    "assignment": "the role has no active permission on this object",
    "spatial": "a governing jurisdiction forbids access, or no replica is reachable",
    "purpose": "the declared purpose is not permitted for this role on this object",
    "minimisation": "this object is not admissible for the declared purpose",
}


def diagnose(policy: Policy, q: Request,
             conjuncts: tuple[str, ...] = engine.CONJUNCTS) -> Denial | None:
    """Return a Denial for a denied request, or None if the request is authorised.

    ``conjuncts`` restricts the diagnosis to one enforcement phase, so that a
    node only evaluates (and reports) what it is entitled to observe.
    """
    conj = engine.evaluate_conjuncts(policy, q, conjuncts)
    failures = [c for c in engine.CONJUNCTS if c in conj and not conj[c]]
    if not failures:
        return None

    first = failures[0]
    return Denial(
        failing_conjunct=first,
        enforcement_point=engine.ENFORCEMENT_POINT[first],
        responsible_elements=_responsible(policy, q, first),
        all_failures=failures,
        message=_HUMAN[first],
    )


def _responsible(policy: Policy, q: Request, conjunct: str) -> list[str]:
    """The specific policy entries implicated in the first failure."""
    if conjunct == "activation":
        assigned = [f"UA({q.u},{r})" for (u, r) in policy.ua if u == q.u]
        return assigned or [f"no UA edge for user {q.u}"]
    if conjunct == "locus":
        return [f"rho_U({q.u})={sorted(policy.rho_u.get(q.u, ()))}", f"requested locus={q.l}"]
    if conjunct == "assignment":
        return [f"no active PA reaching ({q.r},{q.o}) at t={q.t}"]
    if conjunct == "spatial":
        return [
            f"rho_G({q.o})={sorted(policy.rho_g.get(q.o, ()))}",
            f"rho_S({q.o})={sorted(policy.rho_s.get(q.o, ()))}",
            f"requested locus={q.l}",
        ]
    if conjunct == "purpose":
        return [f"Pi_t({q.r},{q.o})={sorted(engine.pi_t(policy, q.r, q.o, q.t))}",
                f"requested purpose={q.p}"]
    if conjunct == "minimisation":
        return [f"Delta({q.p})={sorted(policy.delta_of(q.p))}", f"requested object={q.o}"]
    return []

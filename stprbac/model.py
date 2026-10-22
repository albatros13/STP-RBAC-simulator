"""The STP-RBAC policy model, mirroring Definition 1 of the paper field-for-field.

Spatio-Temporal Purpose-aware RBAC for Federated Data Processing. A policy is a
tuple

    Theta = (U, R, O, L, P,
             UA, PA, H,
             tau_U, tau_P, tau_H,
             rho_U, rho_G, rho_S, Gamma, Pi, Delta, SoD)

We keep the paper's names deliberately. The value of a formal model is lost the
moment the code and the paper diverge, so nothing is "simplified" here.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property

from .intervals import IntervalSet


@dataclass(frozen=True)
class Request:
    """An access request q = (u, r, o, p, l, t).

    User ``u`` acting in role ``r`` from jurisdiction ``l`` requests object ``o``
    for purpose ``p`` at time ``t``.
    """

    u: str  # user
    r: str  # role
    o: str  # object
    p: str  # purpose
    l: str  # jurisdiction (locus) the request is made from
    t: int  # time


@dataclass(frozen=True)
class Policy:
    """An STP-RBAC policy (Definition 1)."""

    users: frozenset[str]
    roles: frozenset[str]
    objects: frozenset[str]
    labels: frozenset[str]                       # L: jurisdictional labels
    purposes: frozenset[str]                     # P: processing purposes

    ua: dict[tuple[str, str], IntervalSet]       # UA with tau_U : (u, r) -> I
    pa: dict[tuple[str, str], IntervalSet]       # PA with tau_P : (r, o) -> I
    h: dict[tuple[str, str], IntervalSet]        # H  with tau_H : (senior, junior) -> I

    rho_u: dict[str, frozenset[str]]             # user   -> admissible loci
    rho_g: dict[str, frozenset[str]]             # object -> GOVERNING regimes
    rho_s: dict[str, frozenset[str]]             # object -> STORAGE sites
    gamma: frozenset[tuple[str, str]]            # cross-jurisdiction access (l, l')
    pi: dict[tuple[str, str], frozenset[str]]    # (r, o) -> permitted purposes
    delta: dict[str, frozenset[str]]             # purpose -> admissible objects
    sod: frozenset[frozenset[str]]               # unordered conflicting role pairs

    def __post_init__(self) -> None:
        # Reject anything Definition 1 does not admit. A malformed policy is
        # not merely untidy: a missing rho_G entry, for instance, makes the
        # universal in RegionOK vacuously true and silently opens the object.
        problems = _validate(self)
        if problems:
            raise ValueError("invalid STP-RBAC policy:\n  - " + "\n  - ".join(problems))

    # ---- indexes (built lazily, once per policy) -------------------------
    @cached_property
    def h_succ(self) -> dict[str, tuple[tuple[str, IntervalSet], ...]]:
        """senior -> ((junior, tau_H), ...): adjacency of H for traversal."""
        out: dict[str, list[tuple[str, IntervalSet]]] = {}
        for (s, j), iv in self.h.items():
            out.setdefault(s, []).append((j, iv))
        return {k: tuple(v) for k, v in out.items()}

    @cached_property
    def ua_by_user(self) -> dict[str, tuple[tuple[str, IntervalSet], ...]]:
        """user -> ((role, tau_U), ...): UA indexed by user."""
        out: dict[str, list[tuple[str, IntervalSet]]] = {}
        for (u, r), iv in self.ua.items():
            out.setdefault(u, []).append((r, iv))
        return {k: tuple(v) for k, v in out.items()}

    # ---- convenience accessors (default to empty / never) ---------------
    def tau_u(self, u: str, r: str) -> IntervalSet:
        return self.ua.get((u, r), IntervalSet())

    def tau_p(self, r: str, o: str) -> IntervalSet:
        return self.pa.get((r, o), IntervalSet())

    def tau_h(self, senior: str, junior: str) -> IntervalSet:
        return self.h.get((senior, junior), IntervalSet())

    def pi_of(self, r: str, o: str) -> frozenset[str]:
        return self.pi.get((r, o), frozenset())

    def delta_of(self, p: str) -> frozenset[str]:
        return self.delta.get(p, frozenset())


def _validate(p: Policy) -> list[str]:
    """Check the side conditions of Definition 1; return a list of violations."""
    errs: list[str] = []

    def unknown(kind: str, where: str, names, domain) -> None:
        bad = sorted(set(names) - domain)
        if bad:
            errs.append(f"{where}: unknown {kind} {bad}")

    for (u, r) in p.ua:
        unknown("user", f"UA({u},{r})", [u], p.users)
        unknown("role", f"UA({u},{r})", [r], p.roles)
    for (r, o) in p.pa:
        unknown("role", f"PA({r},{o})", [r], p.roles)
        unknown("object", f"PA({r},{o})", [o], p.objects)
    for (s, j) in p.h:
        unknown("role", f"H({s},{j})", [s, j], p.roles)

    # rho_U, rho_G, rho_S are total functions into non-empty label sets.
    for name, rho, domain, kind in (
        ("rho_U", p.rho_u, p.users, "user"),
        ("rho_G", p.rho_g, p.objects, "object"),
        ("rho_S", p.rho_s, p.objects, "object"),
    ):
        missing = sorted(x for x in domain if not rho.get(x))
        if missing:
            errs.append(f"{name}: no (or empty) entry for {kind}(s) {missing}")
        unknown(kind, name, rho.keys(), domain)
        for x, labels in rho.items():
            unknown("label", f"{name}({x})", labels, p.labels)

    for (a, b) in p.gamma:
        unknown("label", f"Gamma({a},{b})", [a, b], p.labels)
    missing_refl = sorted(l for l in p.labels if (l, l) not in p.gamma)
    if missing_refl:
        errs.append(f"Gamma must be reflexive; missing (l,l) for {missing_refl}")

    # Pi is defined on PA; an absent entry means the empty purpose set.
    for (r, o), purposes in p.pi.items():
        if (r, o) not in p.pa:
            errs.append(f"Pi({r},{o}): ({r},{o}) is not in PA")
        unknown("purpose", f"Pi({r},{o})", purposes, p.purposes)
    for purpose, objs in p.delta.items():
        unknown("purpose", "Delta", [purpose], p.purposes)
        unknown("object", f"Delta({purpose})", objs, p.objects)

    for pair in p.sod:
        if len(pair) != 2:
            errs.append(f"SoD pair {sorted(pair)} must contain two distinct roles")
        unknown("role", f"SoD{sorted(pair)}", pair, p.roles)

    if _has_cycle(p.h):
        errs.append("role hierarchy H must be acyclic")
    return errs


def _has_cycle(h: dict[tuple[str, str], IntervalSet]) -> bool:
    """Cycle detection over the (time-agnostic) edge set of H.

    Kahn's algorithm: iterative, so arbitrarily deep hierarchies cannot hit
    Python's recursion limit.
    """
    indeg: dict[str, int] = {}
    adj: dict[str, list[str]] = {}
    for (s, j) in h:
        adj.setdefault(s, []).append(j)
        indeg.setdefault(s, 0)
        indeg[j] = indeg.get(j, 0) + 1
    ready = [n for n, d in indeg.items() if d == 0]
    seen = 0
    while ready:
        n = ready.pop()
        seen += 1
        for j in adj.get(n, ()):
            indeg[j] -= 1
            if indeg[j] == 0:
                ready.append(j)
    return seen < len(indeg)

"""SMT encoding of STP-RBAC (Section 6 of the paper), discharged by Z3.

Two modes share one encoding:

  * ``check``: every interval endpoint is a numeral, so the formula is ground
    apart from the query variables (typically the time ``t``). Polynomial.
  * ``synthesise``: endpoints are free integers with ``a <= b`` asserted, and
    every constituent interval gets a Boolean ``enabled`` flag so a repair may
    drop it. This is where NP-hardness enters.

In both modes the Boolean structure of the policy (Gamma, Pi, Delta, rho_*) is
fixed, as in the paper's repair query.

The hierarchy closure Sen_{r,r'}(t) is built two ways:

  * ``unroll``: quantifier-free. Because H is acyclic, unrolling to the
    longest path is the same as one pass over a topological order, so
    Sen(r, x) = OR over in-edges (y, x) of Sen(r, y) AND live_(y,x)(t).
    Works in both modes.
  * ``fixedpoint``: the Horn rules of Section 6 handed to Z3's Fixedpoint
    engine (Spacer). Check mode only (rules need numeral endpoints).

Queries implemented (Section 6, "Queries"):

  * :func:`find_access`       unauthorised access: a witness for a pattern
  * :func:`temporal_sod`      temporal SoD violations, with a witness time
  * :func:`dead_permissions`  (r, o, p) with p in Pi(r, o) that can never fire
  * :func:`repair`            minimal window shrinkage restoring safety while
                              keeping required requests authorised

plus :class:`SmtEngine` for single-request decisions and an unsat-core
explanation (the E6 baseline presentation).

Universally quantified safety ("no t in [lo, hi] authorises the pattern") is
kept quantifier-free by a breakpoint argument generalising Lemma 3 to
symbolic endpoints: Auth is a positive (negation-free) combination of
``a <= t <= b`` atoms, so the set of times where it holds is a finite union
of intervals, each of which starts at ``lo`` or at some window's lower
endpoint ``a``. Checking those candidate instants is therefore exact.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field, replace
from typing import Iterable, Literal

import z3

from . import engine
from .intervals import IntervalSet
from .model import Policy, Request, topological_order

Mode = Literal["check", "synthesise"]
EdgeKey = tuple[str, str, str]        # ("UA"|"PA"|"H", x, y)


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------
@dataclass
class Window:
    """One constituent interval [a, b] of one edge's validity set."""

    a: z3.ArithRef
    b: z3.ArithRef
    enabled: z3.BoolRef
    original: tuple[int, int]


@dataclass(frozen=True)
class AccessPattern:
    """A set of requests; ``None`` means "any". Times are inclusive bounds."""

    u: str | None = None
    r: str | None = None
    o: str | None = None
    p: str | None = None
    l: str | None = None
    t_from: int | None = None
    t_to: int | None = None

    def domains(self, policy: Policy) -> tuple[list[str], ...]:
        """Candidate values for (u, r, o, p, l): the fixed one, or all, sorted."""
        dom = lambda v, xs: [v] if v is not None else sorted(xs)  # noqa: E731
        return (dom(self.u, policy.users), dom(self.r, policy.roles),
                dom(self.o, policy.objects), dom(self.p, policy.purposes),
                dom(self.l, policy.labels))

    def admits_time(self, t: int) -> bool:
        return (self.t_from is None or t >= self.t_from) and (self.t_to is None or t <= self.t_to)


class Encoding:
    """The Section 6 encoding of one policy, in one mode."""

    def __init__(self, policy: Policy, mode: Mode = "check"):
        if mode not in ("check", "synthesise"):
            raise ValueError(f"unknown mode {mode!r}")
        self.policy = policy
        self.mode = mode
        self.side: list[z3.BoolRef] = []        # well-formedness of free endpoints
        self.windows: dict[EdgeKey, list[Window]] = {}
        for kind, rel in policy.temporal_relations().items():
            for (x, y), iv in rel.items():
                self.windows[(kind, x, y)] = [
                    self._window(kind, x, y, j, a, b) for j, (a, b) in enumerate(iv.intervals)
                ]

        self._h_in: dict[str, list[str]] = {}
        for (s, j) in policy.h:
            self._h_in.setdefault(j, []).append(s)
        self._topo = topological_order(policy.roles, policy.h)
        self._reach: dict[str, frozenset[str]] = {}
        self._sen: dict[tuple[str, int], dict[str, z3.BoolRef]] = {}

    def _window(self, kind: str, x: str, y: str, j: int, a: int, b: int) -> Window:
        if self.mode == "check":
            return Window(z3.IntVal(a), z3.IntVal(b), z3.BoolVal(True), (a, b))
        name = f"{kind}[{x},{y}]#{j}"
        wa, wb = z3.Int(f"a:{name}"), z3.Int(f"b:{name}")
        self.side.append(wa <= wb)
        return Window(wa, wb, z3.Bool(f"en:{name}"), (a, b))

    # ---- temporal atoms -------------------------------------------------
    def live(self, edge: EdgeKey, t: z3.ArithRef) -> z3.BoolRef:
        """live_x(t) <-> OR_j (a_xj <= t <= b_xj)."""
        terms = []
        for w in self.windows.get(edge, ()):
            atom = z3.And(w.a <= t, t <= w.b)
            terms.append(atom if self.mode == "check" else z3.And(w.enabled, atom))
        return _or(terms)

    def _static_reach(self, r: str) -> frozenset[str]:
        """Roles reachable from r in H ignoring time (r included)."""
        if r not in self._reach:
            seen, stack = {r}, [r]
            while stack:
                for j, _ in self.policy.h_succ.get(stack.pop(), ()):
                    if j not in seen:
                        seen.add(j)
                        stack.append(j)
            self._reach[r] = frozenset(seen)
        return self._reach[r]

    def sen_from(self, r: str, t: z3.ArithRef) -> dict[str, z3.BoolRef]:
        """{ x: Sen_{r,x}(t) } for every x statically below r (unrolled closure)."""
        key = (r, t.get_id())
        if key not in self._sen:
            reach = self._static_reach(r)
            sen: dict[str, z3.BoolRef] = {r: z3.BoolVal(True)}
            for x in self._topo:
                if x == r or x not in reach:
                    continue
                sen[x] = _or([z3.And(sen[y], self.live(("H", y, x), t))
                              for y in self._h_in.get(x, ()) if y in sen])
            self._sen[key] = sen
        return self._sen[key]

    # ---- the six conjuncts (Definition 6 as encoded in Section 6) --------
    def activation(self, u: str, r: str, t: z3.ArithRef) -> z3.BoolRef:
        terms = []
        for rprime, _ in self.policy.ua_by_user.get(u, ()):
            below = self.sen_from(rprime, t)
            if r in below:
                terms.append(z3.And(self.live(("UA", u, rprime), t), below[r]))
        return _or(terms)

    def locus(self, u: str, l: str) -> z3.BoolRef:
        return z3.BoolVal(l in self.policy.rho_u.get(u, ()))

    def assignment(self, r: str, o: str, t: z3.ArithRef) -> z3.BoolRef:
        return _or([z3.And(s, self.live(("PA", r2, o), t))
                    for r2, s in self.sen_from(r, t).items() if (r2, o) in self.policy.pa])

    def spatial(self, l: str, o: str) -> z3.BoolRef:
        p = self.policy
        gov, sto = p.rho_g.get(o, ()), p.rho_s.get(o, ())
        gamma = lambda a, b: z3.BoolVal((a, b) in p.gamma)  # noqa: E731
        return z3.And(
            z3.And([z3.Implies(z3.BoolVal(lg in gov), gamma(l, lg)) for lg in sorted(p.labels)]),
            z3.Or([z3.And(z3.BoolVal(ls in sto), gamma(l, ls)) for ls in sorted(p.labels)]),
        )

    def purpose(self, r: str, o: str, p: str, t: z3.ArithRef) -> z3.BoolRef:
        # Fused with assignment: the purpose witness r2 must be the same role
        # whose permission on o is live (Section 6, "Authorisation").
        return _or([z3.And(s, self.live(("PA", r2, o), t))
                    for r2, s in self.sen_from(r, t).items()
                    if (r2, o) in self.policy.pa and p in self.policy.pi_of(r2, o)])

    def minimisation(self, o: str, p: str) -> z3.BoolRef:
        return z3.BoolVal(o in self.policy.delta_of(p))

    def conjuncts(self, u: str, r: str, o: str, p: str, l: str,
                  t: z3.ArithRef) -> dict[str, z3.BoolRef]:
        return {
            "activation": self.activation(u, r, t),
            "locus": self.locus(u, l),
            "assignment": self.assignment(r, o, t),
            "spatial": self.spatial(l, o),
            "purpose": self.purpose(r, o, p, t),
            "minimisation": self.minimisation(o, p),
        }

    def auth(self, u: str, r: str, o: str, p: str, l: str, t: z3.ArithRef) -> z3.BoolRef:
        return z3.And(list(self.conjuncts(u, r, o, p, l, t).values()))

    def static_ok(self, u: str, o: str, p: str, l: str) -> bool:
        """The time-free conjuncts, which are ground in both modes."""
        expr = z3.And(self.locus(u, l), self.spatial(l, o), self.minimisation(o, p))
        return z3.is_true(z3.simplify(expr))

    # ---- pattern expansion ---------------------------------------------
    def candidates(self, pat: AccessPattern) -> Iterable[tuple[str, str, str, str, str]]:
        """Concrete (u, r, o, p, l) matching the pattern whose ground part holds."""
        us, rs, os_, ps, ls = pat.domains(self.policy)
        for u, o, p, l in itertools.product(us, os_, ps, ls):
            if not self.static_ok(u, o, p, l):
                continue
            for r in rs:
                yield (u, r, o, p, l)

    def lower_endpoints_in(self, formula: z3.ExprRef) -> list[z3.ArithRef]:
        """Lower endpoints of the windows that ``formula`` actually mentions.

        Only these can start an interval on which the formula holds, so they
        are the candidate instants for the breakpoint argument.
        """
        if self.mode == "check":
            # numeral endpoints leave no trace in the formula: use them all
            return [z3.IntVal(v) for v in sorted({w.original[0] for w in self.all_windows()})]
        names = _const_names(formula)
        return [w.a for w in self.all_windows() if str(w.a) in names]

    def all_windows(self) -> Iterable[Window]:
        for ws in self.windows.values():
            yield from ws


def _or(terms: list[z3.BoolRef]) -> z3.BoolRef:
    if not terms:
        return z3.BoolVal(False)
    return terms[0] if len(terms) == 1 else z3.Or(terms)


def _const_names(e: z3.ExprRef) -> set[str]:
    """Names of the uninterpreted constants occurring in ``e``."""
    out: set[str] = set()
    seen: set[int] = set()
    stack = [e]
    while stack:
        x = stack.pop()
        if x.get_id() in seen:
            continue
        seen.add(x.get_id())
        if z3.is_const(x) and x.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            out.add(x.decl().name())
        stack.extend(x.children())
    return out


def _time_bounds(t: z3.ArithRef, pat: AccessPattern) -> list[z3.BoolRef]:
    out = []
    if pat.t_from is not None:
        out.append(t >= pat.t_from)
    if pat.t_to is not None:
        out.append(t <= pat.t_to)
    return out


# ---------------------------------------------------------------------------
# Generic entry point (plan, E3)
# ---------------------------------------------------------------------------
def encode(policy: Policy, mode: Mode, query: AccessPattern,
           enc: Encoding | None = None) -> tuple[z3.Solver, z3.ArithRef, dict]:
    """Solver asserting "some request matching ``query`` is authorised".

    Returns ``(solver, t, selectors)`` where ``selectors`` maps a Boolean
    selector to its concrete (u, r, o, p, l): in a model, the true selector
    names the witness.
    """
    enc = enc or Encoding(policy, mode)
    t = z3.Int("t")
    s = z3.Solver()
    s.add(enc.side)
    s.add(_time_bounds(t, query))
    selectors: dict = {}
    for i, cand in enumerate(enc.candidates(query)):
        a = enc.auth(*cand, t)
        if z3.is_false(z3.simplify(a)):
            continue
        sel = z3.Bool(f"sel{i}")
        s.add(z3.Implies(sel, a))
        selectors[sel] = cand
    s.add(_or(list(selectors)))
    return s, t, selectors


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------
def find_access(policy: Policy, pattern: AccessPattern,
                enc: Encoding | None = None) -> Request | None:
    """A request matching ``pattern`` that the policy authorises, or None.

    Use it with a pattern the author believes forbidden: a result is a
    counterexample (Section 6, "Unauthorised access").
    """
    s, t, selectors = encode(policy, "check", pattern, enc)
    if s.check() != z3.sat:
        return None
    m = s.model()
    for sel, (u, r, o, p, l) in selectors.items():
        if z3.is_true(m.eval(sel, model_completion=True)):
            return Request(u, r, o, p, l, m.eval(t, model_completion=True).as_long())
    raise AssertionError("sat model with no true selector")


@dataclass(frozen=True)
class SoDViolation:
    user: str
    roles: tuple[str, str]
    t: int


def temporal_sod(policy: Policy, enc: Encoding | None = None) -> list[SoDViolation]:
    """Every (u, {r1, r2}) with r1, r2 in Act_t(u) for some t, with a witness t."""
    enc = enc or Encoding(policy, "check")
    t = z3.Int("t")
    s = z3.Solver()
    out = []
    for u in sorted(policy.users):
        for pair in sorted(tuple(sorted(p)) for p in policy.sod):
            r1, r2 = pair
            s.push()
            s.add(enc.activation(u, r1, t), enc.activation(u, r2, t))
            if s.check() == z3.sat:
                out.append(SoDViolation(u, pair, s.model().eval(t, model_completion=True).as_long()))
            s.pop()
    return out


def dead_permissions(policy: Policy, enc: Encoding | None = None) -> list[tuple[str, str, str]]:
    """(r, o, p) with p in Pi(r, o) such that no u, l, t authorises (u, r, o, p, l, t)."""
    enc = enc or Encoding(policy, "check")
    dead = []
    for (r, o) in sorted(policy.pa):
        for p in sorted(policy.pi_of(r, o)):
            if find_access(policy, AccessPattern(r=r, o=o, p=p), enc) is None:
                dead.append((r, o, p))
    return dead


# ---------------------------------------------------------------------------
# Single-request decisions
# ---------------------------------------------------------------------------
class SmtEngine:
    """Decide individual requests with Z3 (check mode, unrolled closure).

    The encoding is built once; each request is a push / assert / check / pop
    on a persistent solver, with ``t`` a single shared integer so the
    unrolled closure is reused across requests.
    """

    def __init__(self, policy: Policy):
        self.policy = policy
        self.enc = Encoding(policy, "check")
        self.t = z3.Int("t")
        self.solver = z3.Solver()

    def _check(self, q: Request, formulas: list[z3.BoolRef]) -> z3.CheckSatResult:
        s = self.solver
        s.push()
        s.add(self.t == q.t, *formulas)
        res = s.check()
        s.pop()
        return res

    def auth(self, q: Request) -> bool:
        return self._check(q, [self.enc.auth(q.u, q.r, q.o, q.p, q.l, self.t)]) == z3.sat

    def evaluate_conjuncts(self, q: Request) -> dict[str, bool]:
        conj = self.enc.conjuncts(q.u, q.r, q.o, q.p, q.l, self.t)
        return {n: self._check(q, [e]) == z3.sat for n, e in conj.items()}

    def unsat_core(self, q: Request) -> list[str] | None:
        """Raw Z3 unsat core over the six named conjuncts, or None if authorised.

        This is the baseline presentation for E6. A core is *a* set of
        jointly unsatisfiable conjuncts, not necessarily the first failure in
        the fixed order that :func:`stprbac.diagnose.diagnose` reports.
        """
        s = z3.Solver()
        s.set(unsat_core=True)
        s.add(self.t == q.t)
        for n, e in self.enc.conjuncts(q.u, q.r, q.o, q.p, q.l, self.t).items():
            s.assert_and_track(e, z3.Bool(n))
        if s.check() == z3.sat:
            return None
        return sorted((str(c) for c in s.unsat_core()), key=engine.CONJUNCTS.index)


class FixedpointEngine:
    """Decide requests with the Horn-rule closure on Z3's Fixedpoint (Spacer).

    Relations over integer-coded entities and time:

        sen(r, r', t)      r >=_t r'
        act(u, r, t)       r in Act_t(u)
        grant(r, o, p, t)  fused effective assignment + purpose

    The time-free conjuncts are ground and are evaluated from the encoding.
    """

    def __init__(self, policy: Policy):
        self.policy = policy
        self.enc = Encoding(policy, "check")
        ids = lambda xs: {x: i for i, x in enumerate(sorted(xs))}  # noqa: E731
        self.rid, self.uid = ids(policy.roles), ids(policy.users)
        self.oid, self.pid = ids(policy.objects), ids(policy.purposes)

        I, B = z3.IntSort(), z3.BoolSort()
        self.sen = z3.Function("sen", I, I, I, B)
        self.act = z3.Function("act", I, I, I, B)
        self.grant = z3.Function("grant", I, I, I, I, B)
        fp = z3.Fixedpoint()
        fp.set(engine="spacer")
        fp.register_relation(self.sen, self.act, self.grant)
        R, T = z3.Ints("R T")
        fp.declare_var(R, T)
        self.t = z3.Int("tq")
        fp.declare_var(self.t)

        within = lambda ab: [T >= ab[0], T <= ab[1]]  # noqa: E731
        fp.rule(self.sen(R, R, T))
        for (s, j), iv in policy.h.items():
            for ab in iv.intervals:
                fp.rule(self.sen(R, self.rid[j], T), [self.sen(R, self.rid[s], T), *within(ab)])
        for (u, r2), iv in policy.ua.items():
            for ab in iv.intervals:
                fp.rule(self.act(self.uid[u], R, T), [self.sen(self.rid[r2], R, T), *within(ab)])
        for (r2, o), iv in policy.pa.items():
            for p in policy.pi_of(r2, o):
                for ab in iv.intervals:
                    fp.rule(self.grant(R, self.oid[o], self.pid[p], T),
                            [self.sen(R, self.rid[r2], T), *within(ab)])
        self.fp = fp

    def auth(self, q: Request) -> bool:
        if not self.enc.static_ok(q.u, q.o, q.p, q.l):
            return False
        r = self.rid[q.r]
        goal = z3.And(self.t == q.t,
                      self.act(self.uid[q.u], r, self.t),
                      self.grant(r, self.oid[q.o], self.pid[q.p], self.t))
        return self.fp.query(goal) == z3.sat


# ---------------------------------------------------------------------------
# Repair (synthesise mode)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class RepairEdit:
    edge: EdgeKey
    before: IntervalSet
    after: IntervalSet


@dataclass
class RepairResult:
    policy: Policy
    cost: int                                   # total time points removed
    edits: list[RepairEdit] = field(default_factory=list)


def repair(policy: Policy, forbidden: Iterable[AccessPattern],
           required: Iterable[Request] = (), timeout_ms: int | None = None) -> RepairResult | None:
    """Shrink validity windows minimally so no forbidden pattern is authorised.

    Every constituent interval may be narrowed or dropped, never widened
    (repair restores safety; it does not grant). ``required`` requests must
    stay authorised. The objective is total window shrinkage, counted in time
    points. Returns None if no shrink-only repair exists; raises TimeoutError
    if the solver gives up (``timeout_ms``).
    """
    enc = Encoding(policy, "synthesise")
    opt = z3.Optimize()
    if timeout_ms is not None:
        opt.set(timeout=timeout_ms)
    opt.add(enc.side)

    cost_terms = []
    for w in enc.all_windows():
        oa, ob = w.original
        opt.add(z3.Implies(w.enabled, z3.And(w.a >= oa, w.b <= ob)))
        cost_terms.append(z3.If(w.enabled, (w.a - oa) + (ob - w.b), ob - oa + 1))

    for q in required:
        opt.add(enc.auth(q.u, q.r, q.o, q.p, q.l, z3.IntVal(q.t)))

    # Safety, quantifier-free: see the module docstring for why checking the
    # lower endpoints (and the pattern's own lower bound) is exact. Only the
    # windows a candidate's Auth formula mentions can contribute an endpoint.
    probe = z3.Int("t_probe")
    for pat in forbidden:
        for cand in enc.candidates(pat):
            shape = enc.auth(*cand, probe)
            if z3.is_false(z3.simplify(shape)):
                continue
            instants = enc.lower_endpoints_in(shape)
            if pat.t_from is not None:
                instants.append(z3.IntVal(pat.t_from))
            for c in instants:
                opt.add(z3.Implies(z3.And(_time_bounds(c, pat)),
                                   z3.Not(enc.auth(*cand, c))))

    cost = z3.Sum(cost_terms) if cost_terms else z3.IntVal(0)
    opt.minimize(cost)
    res = opt.check()
    if res == z3.unknown:
        raise TimeoutError(f"repair: solver returned unknown ({opt.reason_unknown()})")
    if res != z3.sat:
        return None
    m = opt.model()

    val = lambda e: m.eval(e, model_completion=True)  # noqa: E731
    old = policy.temporal_relations()
    new: dict[str, dict] = {kind: {} for kind in old}
    edits = []
    for (kind, x, y), ws in enc.windows.items():
        after = IntervalSet((val(w.a).as_long(), val(w.b).as_long())
                            for w in ws if z3.is_true(val(w.enabled)))
        before = old[kind][(x, y)]
        new[kind][(x, y)] = after
        if after != before:
            edits.append(RepairEdit((kind, x, y), before, after))
    repaired = replace(policy, ua=new["UA"], pa=new["PA"], h=new["H"])
    return RepairResult(repaired, val(cost).as_long(), edits)

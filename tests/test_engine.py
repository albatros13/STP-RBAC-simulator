"""Engine, model and interval tests. Standard library only:

    python -m unittest discover -s tests -v
"""
from __future__ import annotations

import random
import time
import unittest

from generators.synthetic import random_small
from scenarios.pharma_hospital import build_policy
from stprbac import diagnose, engine
from stprbac.intervals import IntervalSet, always
from stprbac.model import Policy, Request
from stprbac.serde import policy_from_dict, policy_to_dict

A = always()


def tiny_policy(**overrides) -> Policy:
    """One user, one role, one object; the request below is authorised."""
    base = dict(
        users=frozenset({"u"}), roles=frozenset({"r"}), objects=frozenset({"o"}),
        labels=frozenset({"EU", "US"}), purposes=frozenset({"p"}),
        ua={("u", "r"): A}, pa={("r", "o"): A}, h={},
        rho_u={"u": frozenset({"US"})}, rho_g={"o": frozenset({"US"})},
        rho_s={"o": frozenset({"US"})},
        gamma=frozenset({("US", "US"), ("EU", "EU")}),
        pi={("r", "o"): frozenset({"p"})}, delta={"p": frozenset({"o"})},
        sod=frozenset(),
    )
    base.update(overrides)
    return Policy(**base)


TINY_Q = Request("u", "r", "o", "p", "US", 5)


# ---------------------------------------------------------------------------
# Reference oracle: the original whole-policy fixpoint closure, kept verbatim
# in spirit as a deliberately naive implementation (plan, section 0.4 check 1).
# ---------------------------------------------------------------------------
def _naive_closure(policy: Policy, t: int) -> dict[str, set[str]]:
    succ = {r: {r} for r in policy.roles}
    edges = [(s, j) for (s, j), iv in policy.h.items() if t in iv]
    changed = True
    while changed:
        changed = False
        for s, j in edges:
            below = succ.setdefault(s, {s})
            new = succ.get(j, {j})
            if not new <= below:
                below |= new
                changed = True
    return succ


def auth_naive(policy: Policy, q: Request) -> dict[str, bool]:
    ge = _naive_closure(policy, q.t)
    act = set()
    for (u, r), iv in policy.ua.items():
        if u == q.u and q.t in iv:
            act |= ge[r]
    inherited = [r for r in ge[q.r] if q.t in policy.tau_p(r, q.o)]
    purposes = set().union(*(policy.pi_of(r, q.o) for r in inherited)) if inherited else set()
    gov, sto = policy.rho_g[q.o], policy.rho_s[q.o]
    return {
        "activation": q.r in act,
        "locus": q.l in policy.rho_u[q.u],
        "assignment": bool(inherited),
        "spatial": all((q.l, g) in policy.gamma for g in gov)
                   and any((q.l, s) in policy.gamma for s in sto),
        "purpose": q.p in purposes,
        "minimisation": q.o in policy.delta_of(q.p),
    }


def random_policy(rng: random.Random) -> Policy:
    return random_small(rng)


class IntervalSetTest(unittest.TestCase):
    def test_normalises_touching_and_overlapping(self):
        self.assertEqual(IntervalSet([(4, 6), (1, 3), (5, 9), (20, 20)]).intervals,
                         ((1, 9), (20, 20)))

    def test_membership_and_first_after(self):
        iv = IntervalSet([(1, 3), (10, 12)])
        self.assertEqual([t in iv for t in (0, 1, 3, 4, 10, 13)],
                         [False, True, True, False, True, False])
        self.assertEqual([iv.first_after(t) for t in (0, 2, 5, 13)], [1, 2, 10, None])

    def test_equality_ignores_cached_starts(self):
        self.assertEqual(IntervalSet([(1, 2)]), IntervalSet([(1, 1), (2, 2)]))
        self.assertEqual(hash(IntervalSet([(1, 2)])), hash(IntervalSet([(1, 2)])))


class ValidationTest(unittest.TestCase):
    def assertRejects(self, fragment: str, **overrides):
        with self.assertRaises(ValueError) as cm:
            tiny_policy(**overrides)
        self.assertIn(fragment, str(cm.exception))

    def test_tiny_policy_is_valid(self):
        self.assertTrue(engine.auth(tiny_policy(), TINY_Q))

    def test_missing_rho_g_rejected(self):
        # previously: silently treated as "ungoverned" and authorised
        self.assertRejects("rho_G", rho_g={})

    def test_missing_rho_u_and_rho_s_rejected(self):
        self.assertRejects("rho_U", rho_u={})
        self.assertRejects("rho_S", rho_s={"o": frozenset()})

    def test_gamma_must_be_reflexive(self):
        self.assertRejects("reflexive", gamma=frozenset({("US", "US")}))

    def test_unknown_names_rejected(self):
        # previously: a UA edge to an undeclared role was authorised
        self.assertRejects("unknown role", roles=frozenset())
        self.assertRejects("unknown label", rho_u={"u": frozenset({"MARS"})})
        self.assertRejects("unknown object", delta={"p": frozenset({"o", "x"})})

    def test_pi_must_be_on_pa(self):
        self.assertRejects("not in PA", pi={("r", "o"): frozenset({"p"}),
                                            ("r", "o2"): frozenset({"p"})})

    def test_sod_pairs(self):
        self.assertRejects("two distinct roles", sod=frozenset({frozenset({"r"})}))

    def test_cycle_rejected(self):
        self.assertRejects("acyclic", roles=frozenset({"r", "a", "b"}),
                           h={("r", "a"): A, ("a", "b"): A, ("b", "r"): A})
        self.assertRejects("acyclic", h={("r", "r"): A})

    def test_scenario_is_valid_and_round_trips(self):
        p = build_policy()
        self.assertEqual(policy_to_dict(policy_from_dict(policy_to_dict(p))), policy_to_dict(p))


class EngineTest(unittest.TestCase):
    def test_demo_cases(self):
        p = build_policy()
        cases = [
            (("alice", "clinician", "ehr", "care", "EU", 50), None),
            (("erin", "coordinator_role", "ehr", "care", "EU", 50), None),
            (("dan", "auditor", "consent", "audit", "CH", 150), "activation"),
            (("carol", "analyst", "genome", "research", "EU", 150), "locus"),
            (("carol", "analyst", "report", "reporting", "US", 250), "spatial"),
            (("bob", "data_manager", "ehr", "care", "UK", 50), "purpose"),
        ]
        for args, failing in cases:
            q = Request(*args)
            with self.subTest(q=q):
                self.assertEqual(engine.auth(p, q), failing is None)
                den = diagnose.diagnose(p, q)
                self.assertEqual(den and den.failing_conjunct, failing)

    def test_agrees_with_naive_oracle(self):
        for seed in range(300):
            rng = random.Random(seed)
            p = random_policy(rng)
            for _ in range(40):
                q = Request(
                    rng.choice(sorted(p.users)), rng.choice(sorted(p.roles)),
                    rng.choice(sorted(p.objects)), rng.choice(sorted(p.purposes)),
                    rng.choice(sorted(p.labels)), rng.randint(-5, 100),
                )
                with self.subTest(seed=seed, q=q):
                    self.assertEqual(engine.evaluate_conjuncts(p, q), auth_naive(p, q))

    def test_two_phases_compose_to_auth(self):
        p = build_policy()
        rng = random.Random(0)
        for _ in range(2000):
            q = Request(rng.choice(sorted(p.users)), rng.choice(sorted(p.roles)),
                        rng.choice(sorted(p.objects)), rng.choice(sorted(p.purposes)),
                        rng.choice(sorted(p.labels)), rng.randint(0, 399))
            both = (engine.coordinator_prefilter(p, q).passed
                    and engine.worker_decision(p, q).passed)
            self.assertEqual(both, engine.auth(p, q))

    def test_coordinator_never_reads_purpose(self):
        class Blind:
            u, r, o, l, t = "alice", "clinician", "ehr", "EU", 50

            @property
            def p(self):
                raise AssertionError("coordinator read the purpose")

        p = build_policy()
        self.assertTrue(engine.coordinator_prefilter(p, Blind()).passed)
        self.assertIsNone(diagnose.diagnose(p, Blind(), engine.COORDINATOR_CONJUNCTS))

    def test_deep_hierarchy(self):
        n = 5000  # previously: RecursionError at ~1000, 7 s per request at 800
        roles = [f"r{i}" for i in range(n)]
        p = tiny_policy(
            roles=frozenset(roles), ua={("u", "r0"): A}, pa={(roles[-1], "o"): A},
            h={(roles[i], roles[i + 1]): A for i in range(n - 1)},
            pi={(roles[-1], "o"): frozenset({"p"})},
        )
        q = Request("u", "r0", "o", "p", "US", 5)
        start = time.perf_counter()
        self.assertTrue(engine.auth(p, q))
        self.assertLess(time.perf_counter() - start, 1.0)

    def test_deep_cycle_detected(self):
        n = 5000
        roles = [f"r{i}" for i in range(n)]
        h = {(roles[i], roles[(i + 1) % n]): A for i in range(n)}
        with self.assertRaises(ValueError):
            tiny_policy(roles=frozenset(roles) | {"r"}, h=h)


if __name__ == "__main__":
    unittest.main()

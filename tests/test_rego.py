"""Agreement of the Rego encoding (policies/stprbac.rego) with stprbac.engine.

Needs the ``opa`` binary on PATH; skipped otherwise.

    python -m unittest tests.test_rego -v
"""
from __future__ import annotations

import itertools
import random
import shutil
import unittest
from dataclasses import replace

from generators.synthetic import random_small
from scenarios.pharma_hospital import DEMO_CASES, build_policy
from stprbac import engine, rego
from stprbac.model import Policy, Request

HAVE_OPA = shutil.which("opa") is not None


def expected(policy: Policy, q: Request) -> dict:
    ph = engine.evaluate_phase(policy, q)
    return {"allow": ph.passed, "conjuncts": ph.conjuncts, "first_failure": ph.first_failure}


def times(policy: Policy) -> list[int]:
    """Every interval endpoint and its neighbours, plus one point inside."""
    pts = set()
    for rel in policy.temporal_relations().values():
        for a, b in (ab for iv in rel.values() for ab in iv.intervals):
            pts |= {a - 1, a, (a + b) // 2, b, b + 1}
    return sorted(pts)


def all_requests(policy: Policy) -> list[Request]:
    return [Request(u, r, o, p, l, t)
            for u, r, o, p, l in itertools.product(
                sorted(policy.users), sorted(policy.roles), sorted(policy.objects),
                sorted(policy.purposes), sorted(policy.labels))
            for t in times(policy)]


@unittest.skipUnless(HAVE_OPA, "opa binary not on PATH")
class TestRegoCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = build_policy()
        cls.opa = rego.OpaCli(cls.policy)

    @classmethod
    def tearDownClass(cls):
        cls.opa.close()

    def test_demo_cases(self):
        got = self.opa.decide_many(c.request for c in DEMO_CASES)
        for case, d in zip(DEMO_CASES, got):
            with self.subTest(q=case.request):
                self.assertEqual(d["allow"], case.first_failure is None)
                self.assertEqual(d["first_failure"], case.first_failure)

    def test_pharma_exhaustive(self):
        qs = all_requests(self.policy)
        got = self.opa.decide_many(qs)
        self.assertEqual(len(got), len(qs))
        self.assertTrue(any(d["allow"] for d in got))
        for q, d in zip(qs, got):
            if d != expected(self.policy, q):
                self.fail(f"{q}: opa={d} engine={expected(self.policy, q)}")

    def test_random_policies(self):
        rng = random.Random(7)
        for i in range(20):
            p = random_small(rng)
            reqs = all_requests(p)
            qs = rng.sample(reqs, k=min(500, len(reqs)))
            with rego.OpaCli(p) as opa:
                got = opa.decide_many(qs)
            for q, d in zip(qs, got):
                if d != expected(p, q):
                    self.fail(f"policy #{i} {q}: opa={d} engine={expected(p, q)}")


@unittest.skipUnless(HAVE_OPA, "opa binary not on PATH")
class TestRegoServer(unittest.TestCase):
    def test_two_phase_over_rest(self):
        policy = build_policy()
        with rego.opa_server(policy) as srv:
            for q in all_requests(policy)[::37]:
                with self.subTest(q=q):
                    pre = engine.coordinator_prefilter(policy, q)
                    post = engine.worker_decision(policy, q)
                    c = srv.decide(q, "coordinator")   # sent without q.p
                    w = srv.decide(q, "worker")
                    self.assertEqual((c["passed"], c["conjuncts"], c["first_failure"]),
                                     (pre.passed, pre.conjuncts, pre.first_failure))
                    self.assertEqual((w["passed"], w["conjuncts"], w["first_failure"]),
                                     (post.passed, post.conjuncts, post.first_failure))
                    self.assertEqual(srv.decide(q)["allow"], engine.auth(policy, q))

    def test_reload_policy(self):
        """One server, re-pointed at another Theta through the Data API."""
        q = DEMO_CASES[0].request
        with rego.opa_server(build_policy()) as srv:
            self.assertTrue(srv.decide(q)["allow"])
            p = build_policy()
            srv.load(replace(p, delta={**p.delta, "care": frozenset()}))
            d = srv.decide(q)
            self.assertFalse(d["allow"])
            self.assertEqual(d["first_failure"], "minimisation")


if __name__ == "__main__":
    unittest.main()

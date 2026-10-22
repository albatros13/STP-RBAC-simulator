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
from scenarios.pharma_hospital import build_policy
from stprbac import engine, rego
from stprbac.model import Policy, Request

HAVE_OPA = shutil.which("opa") is not None


def expected(policy: Policy, q: Request) -> dict:
    cs = engine.evaluate_conjuncts(policy, q)
    first = next((c for c in engine.CONJUNCTS if not cs[c]), None)
    return {"allow": all(cs.values()), "conjuncts": cs, "first_failure": first}


def times(policy: Policy) -> list[int]:
    """Every interval endpoint and its neighbours, plus one point inside."""
    pts = set()
    for iv in itertools.chain(policy.ua.values(), policy.pa.values(), policy.h.values()):
        for a, b in iv.intervals:
            pts |= {a - 1, a, (a + b) // 2, b, b + 1}
    return sorted(pts)


def all_requests(policy: Policy) -> list[Request]:
    return [Request(u, r, o, p, l, t)
            for u, r, o, p, l in itertools.product(
                sorted(policy.users), sorted(policy.roles), sorted(policy.objects),
                sorted(policy.purposes), sorted(policy.labels))
            for t in times(policy)]


# The demo_client.py cases: (request, allow, first failing conjunct).
DEMO = [
    (Request("alice", "clinician", "ehr", "care", "EU", 50), True, None),
    (Request("erin", "coordinator_role", "ehr", "care", "EU", 50), True, None),
    (Request("dan", "auditor", "consent", "audit", "CH", 150), False, "activation"),
    (Request("carol", "analyst", "genome", "research", "EU", 150), False, "locus"),
    (Request("carol", "analyst", "report", "reporting", "US", 250), False, "spatial"),
    (Request("bob", "data_manager", "ehr", "care", "UK", 50), False, "purpose"),
]


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
        got = self.opa.decide_many(q for q, _, _ in DEMO)
        for (q, allow, first), d in zip(DEMO, got):
            with self.subTest(q=q):
                self.assertEqual(d["allow"], allow)
                self.assertEqual(d["first_failure"], first)

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
            qs = rng.sample(all_requests(p), k=min(500, len(all_requests(p))))
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
        q = DEMO[0][0]
        with rego.opa_server(build_policy()) as srv:
            self.assertTrue(srv.decide(q)["allow"])
            p = build_policy()
            srv.load(replace(p, delta={**p.delta, "care": frozenset()}))
            d = srv.decide(q)
            self.assertFalse(d["allow"])
            self.assertEqual(d["first_failure"], "minimisation")


if __name__ == "__main__":
    unittest.main()

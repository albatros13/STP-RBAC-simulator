"""Seeded synthetic STP-RBAC policy generator (plan, section 0.3).

A first cut: the knobs below cover entity counts, assignment density,
hierarchy density, intervals per edge and Gamma density. The hierarchy is a
random DAG built by fixing a random topological order first, so no rejection
loop is needed.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from stprbac.intervals import IntervalSet
from stprbac.model import Policy, Request


@dataclass(frozen=True)
class Knobs:
    n_users: int = 5
    n_roles: int = 10
    n_objects: int = 6
    n_labels: int = 3
    n_purposes: int = 3
    roles_per_user: int = 3          # max UA edges per user
    pa_density: float = 0.3          # fraction of R x O assigned
    h_density: float = 0.25          # fraction of order-respecting role pairs in H
    max_intervals: int = 3           # constituent intervals per validity set
    horizon: int = 60
    gamma_density: float = 0.4       # extra (non-reflexive) Gamma pairs
    sod_pairs: int = 0


def _interval_set(rng: random.Random, k: Knobs) -> IntervalSet:
    out = []
    for _ in range(rng.randint(1, k.max_intervals)):
        a = rng.randint(0, k.horizon)
        out.append((a, a + rng.randint(0, max(1, k.horizon // 3))))
    return IntervalSet(out)


def generate(knobs: Knobs, seed: int) -> Policy:
    rng = random.Random(seed)
    k = knobs
    users = [f"u{i}" for i in range(k.n_users)]
    roles = [f"r{i}" for i in range(k.n_roles)]
    objects = [f"o{i}" for i in range(k.n_objects)]
    labels = [f"L{i}" for i in range(k.n_labels)]
    purposes = [f"p{i}" for i in range(k.n_purposes)]

    def some(xs: list[str], most: int) -> list[str]:
        return rng.sample(xs, rng.randint(1, min(most, len(xs))))

    ua = {(u, r): _interval_set(rng, k) for u in users for r in some(roles, k.roles_per_user)}
    pa = {(r, o): _interval_set(rng, k)
          for r in roles for o in objects if rng.random() < k.pa_density}
    order = roles[:]
    rng.shuffle(order)
    h = {(order[i], order[j]): _interval_set(rng, k)
         for i in range(len(order)) for j in range(i + 1, len(order))
         if rng.random() < k.h_density}
    gamma = {(l, l) for l in labels} | {
        (a, b) for a in labels for b in labels if rng.random() < k.gamma_density}
    sod: set[frozenset[str]] = set()
    if len(roles) >= 2:
        for _ in range(k.sod_pairs):
            sod.add(frozenset(rng.sample(roles, 2)))

    return Policy(
        users=frozenset(users), roles=frozenset(roles), objects=frozenset(objects),
        labels=frozenset(labels), purposes=frozenset(purposes),
        ua=ua, pa=pa, h=h,
        rho_u={u: frozenset(some(labels, 2)) for u in users},
        rho_g={o: frozenset(some(labels, 2)) for o in objects},
        rho_s={o: frozenset(some(labels, 2)) for o in objects},
        gamma=frozenset(gamma),
        pi={key: frozenset(some(purposes, 2)) for key in pa if rng.random() < 0.8},
        delta={p: frozenset(some(objects, 4)) for p in purposes},
        sod=frozenset(sod),
    )


def random_small(rng: random.Random) -> Policy:
    """A small policy with randomly drawn sizes, for property-style tests."""
    knobs = Knobs(
        n_users=rng.randint(1, 5), n_roles=rng.randint(1, 10),
        n_objects=rng.randint(1, 6), n_labels=rng.randint(1, 4),
        n_purposes=rng.randint(1, 4), sod_pairs=rng.randint(0, 3),
    )
    return generate(knobs, rng.randrange(2**32))


def random_request(p: Policy, rng: random.Random, t_max: int, t_min: int = -5) -> Request:
    """A uniformly drawn request over p's entities, with t in [t_min, t_max]."""
    return Request(rng.choice(sorted(p.users)), rng.choice(sorted(p.roles)),
                   rng.choice(sorted(p.objects)), rng.choice(sorted(p.purposes)),
                   rng.choice(sorted(p.labels)), rng.randint(t_min, t_max))

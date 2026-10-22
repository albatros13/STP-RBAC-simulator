"""The pharmaceutical / hospital collaboration scenario (E1 running example).

A federated study across several jurisdictions. Five roles, six data objects,
five purposes, four project phases on the planning horizon, and five
jurisdictions. Data lives in the regions that govern and store it; workers in
those regions enforce the purpose phase, the coordinator enforces the rest.

This is a deliberately small, hand-encoded instance meant to exercise every
conjunct of Auth and every routing path, not to be exhaustive. Times are
integer points; the horizon is divided into four project phases:

    phase 1: [0, 99]     setup / data collection
    phase 2: [100, 199]  analysis
    phase 3: [200, 299]  reporting
    phase 4: [300, 399]  archival / wind-down
"""
from __future__ import annotations

from stprbac.intervals import IntervalSet, always
from stprbac.model import Policy

# ---- jurisdictions (L) ----------------------------------------------------
EU, UK, US, CH, IN = "EU", "UK", "US", "CH", "IN"

# ---- phases (handy interval shorthands) -----------------------------------
PH1 = IntervalSet([(0, 99)])
PH2 = IntervalSet([(100, 199)])
PH3 = IntervalSet([(200, 299)])
PH4 = IntervalSet([(300, 399)])
PH12 = PH1.union(PH2)
PH23 = PH2.union(PH3)
ALL = always(399)


def build_policy() -> Policy:
    users = frozenset({"alice", "bob", "carol", "dan", "erin"})
    roles = frozenset({
        "coordinator_role", "clinician", "data_manager", "analyst", "auditor",
    })
    objects = frozenset({"ehr", "imaging", "genome", "labresults", "consent", "report"})
    labels = frozenset({EU, UK, US, CH, IN})
    purposes = frozenset({"care", "research", "anonymisation", "audit", "reporting"})

    # -- UA: user -> role, with validity windows (tau_U) --
    ua = {
        ("alice", "clinician"): ALL,          # EU clinician, always on staff
        ("bob", "data_manager"): ALL,         # UK data manager
        ("carol", "analyst"): PH23,           # US analyst, only during analysis+reporting
        ("dan", "auditor"): PH4,              # CH auditor, only in the archival phase
        ("erin", "coordinator_role"): ALL,    # study coordinator (senior role)
    }

    # -- H: role hierarchy senior -> junior, with validity (tau_H) --
    # The coordinator role is senior to clinician and analyst during the study;
    # data_manager is senior to nothing. Auditor stands alone.
    h = {
        ("coordinator_role", "clinician"): ALL,
        ("coordinator_role", "analyst"): PH23,
    }

    # -- PA: role -> object permission, with validity (tau_P) --
    pa = {
        ("clinician", "ehr"): ALL,
        ("clinician", "imaging"): ALL,
        ("clinician", "labresults"): ALL,
        ("data_manager", "ehr"): ALL,
        ("data_manager", "imaging"): ALL,
        ("data_manager", "genome"): ALL,
        ("data_manager", "consent"): ALL,
        ("analyst", "labresults"): PH23,
        ("analyst", "genome"): PH23,
        ("analyst", "report"): PH3,
        ("auditor", "consent"): PH4,
        ("auditor", "report"): PH4,
    }

    # -- rho_U: user -> admissible loci --
    rho_u = {
        "alice": frozenset({EU}),
        "bob": frozenset({UK}),
        "carol": frozenset({US}),
        "dan": frozenset({CH}),
        "erin": frozenset({EU, UK}),   # coordinator may operate from EU or UK
    }

    # -- rho_G: object -> GOVERNING jurisdictions (whose law governs) --
    rho_g = {
        "ehr": frozenset({EU}),
        "imaging": frozenset({EU}),
        "labresults": frozenset({UK}),
        "genome": frozenset({US}),
        "consent": frozenset({EU}),
        "report": frozenset({EU}),
    }

    # -- rho_S: object -> STORAGE sites (where replicas physically sit) --
    rho_s = {
        "ehr": frozenset({EU}),
        "imaging": frozenset({EU}),
        "labresults": frozenset({UK}),
        "genome": frozenset({US}),
        "consent": frozenset({EU}),
        "report": frozenset({EU, UK}),
    }

    # -- Gamma: directed cross-jurisdiction access (l may process l'-data) --
    # Reflexive, plus a few adequacy decisions / bilateral agreements. Notably
    # NOT symmetric and NOT transitive. IN (India) is non-adequate here.
    gamma = frozenset({
        (EU, EU), (UK, UK), (US, US), (CH, CH), (IN, IN),  # reflexive
        (EU, UK), (UK, EU),        # EU <-> UK adequacy (both directions)
        (EU, CH), (CH, EU),        # EU <-> CH adequacy
        (UK, US),                  # UK may process US data (one direction only)
        (EU, US),                  # EU may process US data
        # note: US -> EU is absent, so a US locus may NOT touch EU-governed data
    })

    # -- Pi: (role, object) -> permitted purposes --
    pi = {
        ("clinician", "ehr"): frozenset({"care"}),
        ("clinician", "imaging"): frozenset({"care"}),
        ("clinician", "labresults"): frozenset({"care"}),
        ("data_manager", "ehr"): frozenset({"anonymisation"}),
        ("data_manager", "imaging"): frozenset({"anonymisation"}),
        ("data_manager", "genome"): frozenset({"anonymisation"}),
        ("data_manager", "consent"): frozenset({"audit"}),
        ("analyst", "labresults"): frozenset({"research"}),
        ("analyst", "genome"): frozenset({"research"}),
        ("analyst", "report"): frozenset({"reporting"}),
        ("auditor", "consent"): frozenset({"audit"}),
        ("auditor", "report"): frozenset({"audit"}),
    }

    # -- Delta: purpose -> admissible objects (data minimisation upper bound) --
    delta = {
        "care": frozenset({"ehr", "imaging", "labresults"}),
        "research": frozenset({"labresults", "genome", "report"}),
        "anonymisation": frozenset({"ehr", "imaging", "genome"}),
        "audit": frozenset({"consent", "report"}),
        "reporting": frozenset({"report", "labresults"}),
    }

    # -- SoD: mutually exclusive roles (unordered pairs) --
    sod = frozenset({
        frozenset({"analyst", "auditor"}),        # cannot both analyse and audit
        frozenset({"data_manager", "auditor"}),
    })

    return Policy(
        users=users, roles=roles, objects=objects, labels=labels, purposes=purposes,
        ua=ua, pa=pa, h=h, rho_u=rho_u, rho_g=rho_g, rho_s=rho_s,
        gamma=gamma, pi=pi, delta=delta, sod=sod,
    )


def default_topology() -> dict:
    """One worker per storage region, on consecutive localhost ports."""
    return {
        "policy_module": "scenarios.pharma_hospital",
        "central": {"host": "127.0.0.1", "port": 9000},
        "workers": [
            {"node_id": "eu-hospital", "region": EU, "host": "127.0.0.1",
             "port": 9001, "objects": ["ehr", "imaging", "consent", "report"]},
            {"node_id": "uk-datacentre", "region": UK, "host": "127.0.0.1",
             "port": 9002, "objects": ["labresults", "report"]},
            {"node_id": "us-lab", "region": US, "host": "127.0.0.1",
             "port": 9003, "objects": ["genome"]},
        ],
    }

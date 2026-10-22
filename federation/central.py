"""The Central node: the coordinator of the federation.

The coordinator sees the workflow and the requesting principal but not the data.
It enforces the purpose-INDEPENDENT phase of Auth (Corollary 2):

    activation, locus, effective assignment (PA*_t), spatial (RegionOK).

If a request clears the prefilter, the coordinator routes it to the worker whose
region actually stores the object (rho_S), which runs the purpose-dependent
phase against its private data. The composite decision equals Auth exactly.

Configured from environment variables: PORT, POLICY_FILE.
"""
from __future__ import annotations

import json
import os

import httpx
from fastapi import FastAPI, HTTPException

from stprbac import diagnose
from stprbac.model import Request as StpRequest
from stprbac import engine
from stprbac.serde import policy_from_dict

from .schemas import (
    AccessRequestModel,
    Decision,
    PhaseReport,
    Registration,
    WorkerDecision,
)


def create_central_app(policy) -> FastAPI:
    app = FastAPI(title="STP-RBAC Coordinator (Central node)")
    # node_id -> Registration; and object -> list of node_ids that store it.
    registry: dict[str, Registration] = {}

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "role": "coordinator", "workers": sorted(registry)}

    @app.post("/register")
    async def register(reg: Registration) -> dict:
        registry[reg.node_id] = reg
        print(f"[coordinator] registered worker '{reg.node_id}' "
              f"region={reg.region} objects={reg.objects} at {reg.url}")
        return {"status": "registered", "node_id": reg.node_id}

    @app.get("/nodes")
    async def nodes() -> dict:
        return {nid: r.model_dump() for nid, r in registry.items()}

    def _route(o: str) -> Registration | None:
        """Pick a worker that stores object o and whose region governs/holds it."""
        storage = policy.rho_s.get(o, frozenset())
        # prefer a registered worker whose declared region is a storage site of o
        for reg in registry.values():
            if o in reg.objects and (reg.region in storage or not storage):
                return reg
        # fall back to any worker that declares the object
        for reg in registry.values():
            if o in reg.objects:
                return reg
        return None

    @app.post("/request", response_model=Decision)
    async def request(req: AccessRequestModel) -> Decision:
        q = StpRequest(**req.model_dump())

        # -- Phase 1: coordinator prefilter (purpose-independent) --
        pre = engine.coordinator_prefilter(policy, q)
        coord_report = PhaseReport(
            node="coordinator",
            enforcement_point="coordinator",
            passed=pre.passed,
            conjuncts=pre.conjuncts,
            first_failure=pre.first_failure,
        )
        if not pre.passed:
            den = diagnose.diagnose(policy, q, engine.COORDINATOR_CONJUNCTS)
            return Decision(
                authorised=False, request=req, decided_at="coordinator",
                phases=[coord_report], denial=_denial_dict(den),
            )

        # -- Route to the worker that physically holds the object --
        target = _route(q.o)
        if target is None:
            raise HTTPException(
                status_code=503,
                detail=f"no worker registered for object '{q.o}' "
                       f"(rho_S={sorted(policy.rho_s.get(q.o, ()))})",
            )

        # -- Phase 2: worker decision (purpose-dependent), at the data provider --
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(f"{target.url}/enforce", json=req.model_dump())
            resp.raise_for_status()
            wd = WorkerDecision(**resp.json())

        return Decision(
            authorised=wd.authorised,
            request=req,
            decided_at=wd.node_id,
            phases=[coord_report, wd.phase],
            output=wd.output,
            denial=wd.denial,
        )

    return app


def _denial_dict(den) -> dict | None:
    if den is None:
        return None
    return {
        "failing_conjunct": den.failing_conjunct,
        "enforcement_point": den.enforcement_point,
        "responsible_elements": den.responsible_elements,
        "all_failures": den.all_failures,
        "message": den.message,
    }


def build_from_env() -> FastAPI:
    with open(os.environ["POLICY_FILE"], encoding="utf-8") as fh:
        policy = policy_from_dict(json.load(fh))
    return create_central_app(policy)


if os.environ.get("POLICY_FILE"):
    app = build_from_env()

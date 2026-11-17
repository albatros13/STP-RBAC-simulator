"""The Central node: the coordinator of the federation.

The coordinator sees the workflow and the requesting principal but not the data.
It enforces the purpose-INDEPENDENT phase of Auth (Corollary 2):

    activation, locus, effective assignment (PA*_t), spatial (RegionOK).

If a request clears the prefilter, the coordinator routes it to a worker whose
region witnesses the existential clause of RegionOK, i.e. stores the object
(rho_S) and is reachable from the declared locus (Gamma): assumption T4. That
worker runs the purpose-dependent phase against its private data. The
composite decision equals Auth exactly.

Configured from the environment variable POLICY_FILE.
"""
from __future__ import annotations

import os

import httpx
from fastapi import FastAPI, HTTPException

from stprbac import diagnose, engine
from stprbac.model import Policy
from stprbac.serde import load_policy

from .schemas import AccessRequestModel, Decision, PhaseReport, Registration, WorkerDecision


def create_central_app(policy: Policy,
                       transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    """``transport`` replaces the network for calls to workers (used by tests)."""
    app = FastAPI(title="STP-RBAC Coordinator (Central node)")
    registry: dict[str, Registration] = {}          # node_id -> Registration

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

    def _route(o: str, l: str) -> Registration | None:
        """A worker that holds o in a region witnessing RegionOK's existential
        clause for locus l (assumption T4), or None if there is none.

        Never falls back to a worker outside rho_S(o) or unreachable from l.
        Ties are broken by node id, so the choice does not depend on the order
        in which workers registered.
        """
        sites = engine.witness_sites(policy, l, o)
        return next((reg for _, reg in sorted(registry.items())
                     if o in reg.objects and reg.region in sites), None)

    @app.post("/request", response_model=Decision)
    async def request(req: AccessRequestModel) -> Decision:
        q = req.to_request()

        # -- Phase 1: coordinator prefilter (purpose-independent) --
        pre = engine.coordinator_prefilter(policy, q)
        coord_report = PhaseReport.from_phase("coordinator", "coordinator", pre)
        if not pre.passed:
            den = diagnose.diagnose(policy, q, engine.COORDINATOR_CONJUNCTS)
            return Decision(
                authorised=False, request=req, decided_at="coordinator",
                phases=[coord_report], denial=den and den.to_dict(),
            )

        # -- Route to a replica site that witnesses RegionOK for q.l (T4) --
        target = _route(q.o, q.l)
        if target is None:
            raise HTTPException(
                status_code=503,
                detail=f"no registered worker holds object '{q.o}' in a region "
                       f"reachable from locus '{q.l}' "
                       f"(witness sites={sorted(engine.witness_sites(policy, q.l, q.o))})",
            )

        # -- Phase 2: worker decision (purpose-dependent), at the data provider --
        async with httpx.AsyncClient(timeout=10.0, transport=transport) as client:
            resp = await client.post(f"{target.url}/enforce", json=req.model_dump())
        if resp.status_code == 421:   # worker refused: not a witness site (T4)
            raise HTTPException(status_code=502,
                                detail=f"worker '{target.node_id}' refused the request: "
                                       f"{resp.json().get('detail')}")
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


def build_from_env() -> FastAPI:
    return create_central_app(load_policy(os.environ["POLICY_FILE"]))


# Uvicorn entrypoint: `uvicorn federation.central:app` with POLICY_FILE set.
if os.environ.get("POLICY_FILE"):
    app = build_from_env()

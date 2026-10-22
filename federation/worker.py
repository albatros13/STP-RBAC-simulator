"""A Worker node: one autonomous data-provider domain, typically one region.

A worker holds local datasets (the "raw data") that never leave its boundary,
and enforces the purpose-dependent phase of Auth (Corollary 2): given a request
that already cleared the coordinator's spatio-temporal prefilter, it accepts iff

    p in Pi_t(r, o)  and  o in Delta(p).

On acceptance it "executes" the requested step on its local data and returns
only a data-minimised, authorised output -- the consumer never sees raw data.

Configured entirely from environment variables so the launcher can spawn many
workers as separate processes:

    NODE_ID, REGION, PORT, POLICY_FILE, OBJECTS (comma-separated), CENTRAL_URL
"""
from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from stprbac import diagnose
from stprbac.model import Request as StpRequest
from stprbac import engine
from stprbac.serde import policy_from_dict

from .schemas import AccessRequestModel, PhaseReport, Registration, WorkerDecision


def create_worker_app(node_id: str, region: str, policy, objects: list[str],
                      central_url: str | None = None, self_url: str | None = None) -> FastAPI:
    # Simulated local datasets. This is the raw data that never leaves the node.
    local_data: dict[str, str] = {
        o: f"<raw bytes of '{o}' held in region {region}>" for o in objects
    }

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Announce this worker to the coordinator on startup.
        if central_url and self_url:
            reg = Registration(node_id=node_id, region=region, url=self_url, objects=objects)
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(f"{central_url}/register", json=reg.model_dump())
            except Exception as exc:  # pragma: no cover - best effort on boot
                print(f"[worker {node_id}] could not register with coordinator: {exc}")
        yield

    app = FastAPI(title=f"STP-RBAC Worker :: {node_id} ({region})", lifespan=lifespan)

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "node_id": node_id, "region": region,
                "objects": sorted(objects)}

    @app.post("/enforce", response_model=WorkerDecision)
    async def enforce(req: AccessRequestModel) -> WorkerDecision:
        """Run the purpose-dependent phase and, if it passes, execute the step."""
        q = StpRequest(**req.model_dump())
        phase = engine.worker_decision(policy, q)
        report = PhaseReport(
            node=node_id,
            enforcement_point="worker",
            passed=phase.passed,
            conjuncts=phase.conjuncts,
            first_failure=phase.first_failure,
        )

        if not phase.passed:
            den = diagnose.diagnose(policy, q, engine.WORKER_CONJUNCTS)
            return WorkerDecision(
                node_id=node_id, region=region, authorised=False, phase=report,
                denial=_denial_dict(den),
            )

        # Authorised: process locally and return only a minimised output.
        raw = local_data.get(q.o, f"<unknown object {q.o}>")
        output = (f"processed('{q.o}' for purpose '{q.p}' by role '{q.r}') "
                  f"@ region {region} [derived from {len(raw)} bytes, raw data retained locally]")
        return WorkerDecision(
            node_id=node_id, region=region, authorised=True, phase=report, output=output,
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
    node_id = os.environ["NODE_ID"]
    region = os.environ["REGION"]
    objects = [o for o in os.environ.get("OBJECTS", "").split(",") if o]
    central_url = os.environ.get("CENTRAL_URL")
    self_url = os.environ.get("SELF_URL")
    with open(os.environ["POLICY_FILE"], encoding="utf-8") as fh:
        policy = policy_from_dict(json.load(fh))
    return create_worker_app(node_id, region, policy, objects, central_url, self_url)


# Uvicorn entrypoint: `uvicorn federation.worker:app` with env configured.
if os.environ.get("NODE_ID"):
    app = build_from_env()

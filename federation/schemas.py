"""Wire schemas exchanged between the client, the coordinator, and workers."""
from __future__ import annotations

from pydantic import BaseModel, Field

from stprbac.engine import PhaseResult
from stprbac.model import Request


class AccessRequestModel(BaseModel):
    """An STP-RBAC access request q = (u, r, o, p, l, t)."""

    u: str = Field(..., description="user")
    r: str = Field(..., description="role")
    o: str = Field(..., description="data object")
    p: str = Field(..., description="declared purpose")
    l: str = Field(..., description="jurisdiction (locus) the request is made from")
    t: int = Field(..., description="time (integer point on the planning horizon)")

    def to_request(self) -> Request:
        return Request(**self.model_dump())


class Registration(BaseModel):
    """A worker announcing itself to the coordinator."""

    node_id: str
    region: str
    url: str
    objects: list[str]


class PhaseReport(BaseModel):
    """Outcome of one enforcement phase at one node."""

    node: str
    enforcement_point: str          # "coordinator" | "worker"
    passed: bool
    conjuncts: dict[str, bool]      # conjunct -> verdict, only those this phase owns
    first_failure: str | None = None

    @classmethod
    def from_phase(cls, node: str, enforcement_point: str, phase: PhaseResult) -> "PhaseReport":
        return cls(node=node, enforcement_point=enforcement_point, passed=phase.passed,
                   conjuncts=phase.conjuncts, first_failure=phase.first_failure)


class WorkerDecision(BaseModel):
    """A worker's response to a routed request."""

    node_id: str
    region: str
    authorised: bool
    phase: PhaseReport
    output: str | None = None       # authorised, data-minimised output (never raw data)
    denial: dict | None = None      # structured Denial, if refused here


class Decision(BaseModel):
    """The coordinator's final answer to the client."""

    authorised: bool
    request: AccessRequestModel
    decided_at: str                 # "coordinator" | node_id of the deciding worker
    phases: list[PhaseReport]
    output: str | None = None
    denial: dict | None = None

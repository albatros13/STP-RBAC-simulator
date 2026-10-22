"""STP-RBAC reference core: model, engine, diagnosis, intervals.

Spatio-Temporal Purpose-aware RBAC for Federated Data Processing.
This package is shared by every node in the federation.
"""
from .intervals import IntervalSet, always
from .model import Policy, Request
from . import engine, diagnose

__all__ = ["IntervalSet", "always", "Policy", "Request", "engine", "diagnose"]

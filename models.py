"""
models.py – Shared data models for VENUS_AI.

All interchange between Planner, Executor, and Perceptor uses these
typed dataclasses so the whole pipeline stays JSON-serialisable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class ActionStatus(str, Enum):
    PENDING  = "pending"
    RUNNING  = "running"
    SUCCESS  = "success"
    FAILED   = "failed"
    TIMEOUT  = "timeout"


# ---------------------------------------------------------------------------
# Action schema  (Planner → Executor)
# ---------------------------------------------------------------------------

@dataclass
class Action:
    """A single step the Executor should perform."""

    action_id: str
    """Unique identifier, e.g. 'run_nmap_fast'."""

    tool: str
    """Tool function name, e.g. 'run_nmap'."""

    params: dict[str, Any] = field(default_factory=dict)
    """Keyword arguments forwarded to the tool function."""

    description: str = ""
    """Human-readable description for reporting."""

    status: ActionStatus = ActionStatus.PENDING
    error: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


# ---------------------------------------------------------------------------
# Tool results
# ---------------------------------------------------------------------------

@dataclass
class Port:
    number: int
    protocol: str        # "tcp" | "udp"
    state: str           # "open" | "closed" | "filtered"
    service: str         # "http", "ssh", ...
    version: str = ""


@dataclass
class NmapResult:
    target: str
    ports: list[Port] = field(default_factory=list)
    os_guess: str = ""
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "os_guess": self.os_guess,
            "ports": [asdict(p) for p in self.ports],
            "raw": self.raw,
        }


@dataclass
class Endpoint:
    url: str
    status_code: int
    content_type: str = ""
    interesting: bool = False


@dataclass
class DirsearchResult:
    target: str
    endpoints: list[Endpoint] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "endpoints": [asdict(e) for e in self.endpoints],
            "raw": self.raw,
        }


@dataclass
class Finding:
    title: str
    severity: Severity
    template_id: str
    url: str
    description: str = ""
    remediation: str = ""


@dataclass
class NucleiResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "target": self.target,
            "findings": [],
            "raw": self.raw,
        }
        for f in self.findings:
            fd = asdict(f)
            fd["severity"] = f.severity.value
            d["findings"].append(fd)
        return d


# ---------------------------------------------------------------------------
# Session / pipeline state
# ---------------------------------------------------------------------------

@dataclass
class ActionResult:
    action: Action
    result: dict = field(default_factory=dict)   # JSON-serialisable output

    def to_dict(self) -> dict:
        return {
            "action": self.action.to_dict(),
            "result": self.result,
        }


@dataclass
class PipelineState:
    """Full state for one target, passed between Planner / Executor / Perceptor."""

    target: str
    goal: str = ""
    actions: list[Action] = field(default_factory=list)
    results: list[ActionResult] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "goal": self.goal,
            "actions": [a.to_dict() for a in self.actions],
            "results": [r.to_dict() for r in self.results],
            "summary": self.summary,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

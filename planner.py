"""
planner.py – The Planner component of VENUS_AI.

Responsible for translating a high-level natural-language goal into an
ordered list of :class:`Action` objects.

Architecture note
-----------------
All LLM calls are isolated behind :class:`LLMAgent`.  The class ships with
a *mock* implementation so the full pipeline can be exercised without any
network access.  Swap ``MockLLMBackend`` for ``AnthropicLLMBackend`` (or
your own) to go live.
"""

from __future__ import annotations

import re
import textwrap
from abc import ABC, abstractmethod
from typing import Any

from models import Action, PipelineState


# ---------------------------------------------------------------------------
# LLM back-end interface
# ---------------------------------------------------------------------------

class LLMBackend(ABC):
    """Abstract base – one concrete class per provider."""

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Return the model's text response."""


class MockLLMBackend(LLMBackend):
    """
    Deterministic mock that returns hard-coded responses.

    Replace with a real provider (e.g. Anthropic, OpenAI) by implementing
    :class:`LLMBackend` and passing an instance to :class:`LLMAgent`.
    """

    # Maps normalised goal keywords → action-id lists
    _PLANS: dict[str, list[str]] = {
        "basic-web": [
            "run_nmap_fast",
            "run_dir_enum",
            "run_vuln_scan_http",
        ],
        "recon": [
            "run_nmap_fast",
            "run_dir_enum",
        ],
        "full": [
            "run_nmap_fast",
            "run_nmap_deep",
            "run_dir_enum",
            "run_vuln_scan_http",
        ],
    }

    _SUMMARIES: dict[str, str] = {
        "default": textwrap.dedent("""\
            ## VENUS_AI Assessment Summary

            Target shows an HTTP service on port 80 (Apache 2.4) and SSH on
            port 22.  Directory enumeration found an exposed /admin panel and a
            /backup directory returning 200 OK – both warrant manual review.

            Nuclei identified a missing X-Frame-Options header (Low) and a
            potentially exploitable phpMyAdmin instance (High).

            Recommended next steps:
            1. Authenticate against /admin and test for default credentials.
            2. Investigate /backup for sensitive file exposure.
            3. Patch or remove phpMyAdmin from the public surface.
            4. Add security headers (X-Frame-Options, CSP, HSTS).
        """),
    }

    def complete(self, system: str, user: str) -> str:  # noqa: ARG002
        """Return a plan or summary based on keywords found in *user*."""
        u = user.lower()
        # Summary request (check before plan to avoid keyword collision)
        if "summary" in u or "findings" in u or "write a summary" in u:
            return self._SUMMARIES["default"]
        # Plan request
        if "plan" in u or "actions" in u:
            for key, actions in self._PLANS.items():
                if key in u:
                    return "\n".join(actions)
            return "\n".join(self._PLANS["basic-web"])
        return self._SUMMARIES["default"]


# ---------------------------------------------------------------------------
# LLM Agent
# ---------------------------------------------------------------------------

# Maps action_id → (tool name, default params, human description)
_ACTION_REGISTRY: dict[str, tuple[str, dict[str, Any], str]] = {
    "run_nmap_fast": (
        "run_nmap",
        {"profile": "fast"},
        "Fast Nmap TCP SYN scan (top 1000 ports)",
    ),
    "run_nmap_deep": (
        "run_nmap",
        {"profile": "deep"},
        "Thorough Nmap scan with version/OS detection",
    ),
    "run_dir_enum": (
        "run_dirsearch",
        {},
        "Directory and file enumeration with dirsearch",
    ),
    "run_vuln_scan_http": (
        "run_nuclei",
        {"template_set": "http"},
        "HTTP vulnerability scan with Nuclei templates",
    ),
    "run_vuln_scan_cves": (
        "run_nuclei",
        {"template_set": "cves"},
        "CVE-focused vulnerability scan with Nuclei",
    ),
}


class LLMAgent:
    """
    Facade that exposes planning and summarisation to the rest of the system.

    Parameters
    ----------
    backend:
        An :class:`LLMBackend` instance.  Defaults to :class:`MockLLMBackend`.
    """

    _PLAN_SYSTEM = textwrap.dedent("""\
        You are VENUS_AI, an AI-assisted penetration testing orchestrator.
        Given a target and a goal, output ONLY a newline-separated list of
        action IDs chosen from the registry below.  No explanation, no JSON –
        just the action IDs, one per line.

        Registry:
        {registry}
    """)

    _SUMMARY_SYSTEM = textwrap.dedent("""\
        You are VENUS_AI.  Given structured reconnaissance findings, produce a
        concise professional penetration-test summary in Markdown.  Group
        findings by severity.  Suggest remediation steps.
    """)

    def __init__(self, backend: LLMBackend | None = None) -> None:
        self._backend: LLMBackend = backend or MockLLMBackend()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def plan_actions(self, state: PipelineState) -> list[Action]:
        """
        Ask the LLM to produce an ordered action plan for *state*.

        Returns a list of :class:`Action` objects ready for the Executor.
        """
        registry_text = "\n".join(
            f"  {aid}: {desc}" for aid, (_, _, desc) in _ACTION_REGISTRY.items()
        )
        system = self._PLAN_SYSTEM.format(registry=registry_text)
        user = (
            f"Target: {state.target}\n"
            f"Goal: {state.goal}\n"
            "Plan the actions:"
        )
        raw = self._backend.complete(system, user)
        return self._parse_plan(raw, state.target)

    def summarize(self, state: PipelineState) -> str:
        """
        Ask the LLM to summarise all findings in *state*.

        Returns a Markdown-formatted string.
        """
        findings_text = state.to_json()
        user = (
            f"Target: {state.target}\n"
            f"Goal: {state.goal}\n\n"
            f"Findings (JSON):\n{findings_text}\n\n"
            "Write a summary:"
        )
        return self._backend.complete(self._SUMMARY_SYSTEM, user)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_plan(raw: str, target: str) -> list[Action]:
        """Convert the LLM's newline-separated action-id list into Actions."""
        actions: list[Action] = []
        for line in raw.splitlines():
            aid = line.strip().lower()
            aid = re.sub(r"[^a-z0-9_]", "", aid)   # sanitise
            if not aid:
                continue
            if aid in _ACTION_REGISTRY:
                tool, params, desc = _ACTION_REGISTRY[aid]
                actions.append(
                    Action(
                        action_id=aid,
                        tool=tool,
                        params={**params, "target": target},
                        description=desc,
                    )
                )
            else:
                # Unknown action – log and skip (could extend registry later)
                pass
        return actions

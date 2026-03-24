"""
executor.py – The Executor component of VENUS_AI.

Responsibilities
----------------
* Wrap individual Kali tools (currently *simulated*).
* Run an ordered list of :class:`Action` objects, handling errors and timeouts.
* Persist structured results under ``sessions/<safe_target>/``.

Replacing mocks with real tools
--------------------------------
Each ``run_*`` function currently returns hard-coded sample data.  To wire in
a real tool:

1. Replace the body of the relevant function with a ``subprocess.run`` call.
2. Parse stdout/stderr into the same return dict / dataclass structure.
3. The rest of the pipeline (Perceptor, reporting) requires no changes.

Example skeleton::

    import subprocess, json

    def run_nmap(target: str, profile: str = "fast") -> dict:
        flags = "-T4 --top-ports 1000" if profile == "fast" else "-A -p-"
        proc = subprocess.run(
            ["nmap", *flags.split(), "-oJ", "-", target],
            capture_output=True, text=True, timeout=300,
        )
        return json.loads(proc.stdout)   # nmap JSON output
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Callable

from models import (
    Action,
    ActionResult,
    ActionStatus,
    DirsearchResult,
    Endpoint,
    Finding,
    NmapResult,
    NucleiResult,
    PipelineState,
    Port,
    Severity,
)

logger = logging.getLogger(__name__)

# Root directory where session data is stored
SESSIONS_DIR = Path("sessions")


# ---------------------------------------------------------------------------
# Simulated tool functions
# ---------------------------------------------------------------------------

def run_nmap(target: str, profile: str = "fast", **_: Any) -> dict:
    """
    Simulate an Nmap scan and return a JSON-serialisable result dict.

    Parameters
    ----------
    target:
        IP address or hostname to scan.
    profile:
        ``"fast"``  → top-1000 ports, ``"deep"`` → all ports + version/OS.
    """
    logger.info("[nmap] Scanning %s (profile=%s) …", target, profile)
    time.sleep(0.3)   # simulate latency

    base_ports = [
        Port(22,  "tcp", "open", "ssh",   "OpenSSH 8.9"),
        Port(80,  "tcp", "open", "http",  "Apache httpd 2.4.54"),
        Port(443, "tcp", "open", "https", "Apache httpd 2.4.54"),
    ]
    extra_ports = [
        Port(3306, "tcp", "open",     "mysql",    "MySQL 8.0.32"),
        Port(8080, "tcp", "filtered", "http-alt", ""),
    ] if profile == "deep" else []

    result = NmapResult(
        target=target,
        ports=base_ports + extra_ports,
        os_guess="Linux 5.x (Ubuntu)" if profile == "deep" else "",
        raw={"profile": profile, "simulated": True},
    )
    return result.to_dict()


def run_dirsearch(target: str, **_: Any) -> dict:
    """
    Simulate dirsearch directory enumeration.

    Parameters
    ----------
    target:
        Base URL to enumerate (e.g. ``https://example.com``).
    """
    logger.info("[dirsearch] Enumerating %s …", target)
    time.sleep(0.2)

    base = target.rstrip("/")
    endpoints = [
        Endpoint(f"{base}/",          200, "text/html",        False),
        Endpoint(f"{base}/admin",     200, "text/html",        True),
        Endpoint(f"{base}/login",     200, "text/html",        False),
        Endpoint(f"{base}/backup",    200, "application/zip",  True),
        Endpoint(f"{base}/api/v1",    403, "application/json", False),
        Endpoint(f"{base}/.env",      403, "text/plain",       True),
        Endpoint(f"{base}/phpmyadmin",200, "text/html",        True),
        Endpoint(f"{base}/robots.txt",200, "text/plain",       False),
    ]

    result = DirsearchResult(target=target, endpoints=endpoints,
                             raw={"simulated": True})
    return result.to_dict()


def run_nuclei(target: str, template_set: str = "http", **_: Any) -> dict:
    """
    Simulate a Nuclei vulnerability scan.

    Parameters
    ----------
    target:
        URL to scan.
    template_set:
        ``"http"``  → generic HTTP checks, ``"cves"`` → CVE templates.
    """
    logger.info("[nuclei] Scanning %s (templates=%s) …", target, template_set)
    time.sleep(0.4)

    base = target.rstrip("/")
    common_findings = [
        Finding(
            title="Missing X-Frame-Options Header",
            severity=Severity.LOW,
            template_id="http/headers/x-frame-options",
            url=f"{base}/",
            description="The X-Frame-Options header is not set, allowing clickjacking.",
            remediation="Add 'X-Frame-Options: SAMEORIGIN' to server responses.",
        ),
        Finding(
            title="Exposed phpMyAdmin Instance",
            severity=Severity.HIGH,
            template_id="http/exposed-panels/phpmyadmin-panel",
            url=f"{base}/phpmyadmin",
            description="phpMyAdmin admin panel is publicly accessible.",
            remediation="Restrict /phpmyadmin to internal IPs or remove it.",
        ),
        Finding(
            title="Directory Listing Enabled",
            severity=Severity.MEDIUM,
            template_id="http/misconfiguration/directory-listing",
            url=f"{base}/backup",
            description="The web server returns a directory listing for /backup.",
            remediation="Disable directory listing in Apache/Nginx configuration.",
        ),
    ]
    cve_findings = [
        Finding(
            title="CVE-2021-41773 Apache Path Traversal",
            severity=Severity.CRITICAL,
            template_id="cves/2021/CVE-2021-41773",
            url=f"{base}/cgi-bin/.%2e/.%2e/.%2e/etc/passwd",
            description="Apache 2.4.49 path traversal / RCE vulnerability.",
            remediation="Upgrade Apache to 2.4.51 or later immediately.",
        ),
    ] if template_set == "cves" else []

    result = NucleiResult(
        target=target,
        findings=common_findings + cve_findings,
        raw={"template_set": template_set, "simulated": True},
    )
    return result.to_dict()


# ---------------------------------------------------------------------------
# Tool registry  (maps tool name → callable)
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, Callable[..., dict]] = {
    "run_nmap":      run_nmap,
    "run_dirsearch": run_dirsearch,
    "run_nuclei":    run_nuclei,
}


# ---------------------------------------------------------------------------
# Central Executor
# ---------------------------------------------------------------------------

class Executor:
    """
    Runs an ordered list of :class:`Action` objects and stores the results.

    Parameters
    ----------
    sessions_dir:
        Root path for session storage (default: ``./sessions``).
    default_timeout:
        Per-action timeout in seconds (currently advisory; subprocess timeouts
        are set inside each tool function when using real tools).
    """

    def __init__(
        self,
        sessions_dir: Path | str = SESSIONS_DIR,
        default_timeout: int = 300,
    ) -> None:
        self._sessions_dir = Path(sessions_dir)
        self._timeout = default_timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_pipeline(self, state: PipelineState) -> PipelineState:
        """
        Execute every action in *state.actions* sequentially.

        Results are appended to *state.results* and persisted to disk after
        each step.  The modified *state* is returned.
        """
        session_dir = self._session_dir(state.target)
        session_dir.mkdir(parents=True, exist_ok=True)

        for action in state.actions:
            action.status = ActionStatus.RUNNING
            ar = self._run_action(action)
            state.results.append(ar)
            self._save_result(session_dir, ar)

        self._save_state(session_dir, state)
        return state

    def load_state(self, target: str) -> PipelineState | None:
        """
        Reload a previously saved :class:`PipelineState` from disk.

        Returns ``None`` if no session exists for *target*.
        """
        path = self._session_dir(target) / "state.json"
        if not path.exists():
            return None
        with path.open() as fh:
            raw = json.load(fh)
        return self._deserialise_state(raw)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_action(self, action: Action) -> ActionResult:
        """Dispatch a single action to the appropriate tool function."""
        tool_fn = TOOL_REGISTRY.get(action.tool)
        if tool_fn is None:
            action.status = ActionStatus.FAILED
            action.error = f"Unknown tool: '{action.tool}'"
            logger.error("No tool named '%s'", action.tool)
            return ActionResult(action=action, result={})

        try:
            result = tool_fn(**action.params)
            action.status = ActionStatus.SUCCESS
            return ActionResult(action=action, result=result)
        except TimeoutError:
            action.status = ActionStatus.TIMEOUT
            action.error = "Tool timed out"
            logger.warning("Action '%s' timed out", action.action_id)
            return ActionResult(action=action, result={})
        except Exception as exc:  # noqa: BLE001
            action.status = ActionStatus.FAILED
            action.error = str(exc)
            logger.exception("Action '%s' failed: %s", action.action_id, exc)
            return ActionResult(action=action, result={})

    def _session_dir(self, target: str) -> Path:
        """Return a sanitised path for storing *target*'s session data."""
        safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
        return self._sessions_dir / safe

    def _save_result(self, session_dir: Path, ar: ActionResult) -> None:
        """Persist a single ActionResult as JSON."""
        fname = f"{ar.action.action_id}.json"
        path = session_dir / fname
        with path.open("w") as fh:
            json.dump(ar.to_dict(), fh, indent=2)

    def _save_state(self, session_dir: Path, state: PipelineState) -> None:
        """Persist the entire PipelineState as JSON."""
        path = session_dir / "state.json"
        with path.open("w") as fh:
            fh.write(state.to_json())

    @staticmethod
    def _deserialise_state(raw: dict) -> PipelineState:
        """Reconstruct a PipelineState from a plain dict (minimal; no deep validation)."""
        from models import ActionResult, Action, ActionStatus  # local to avoid circ.
        actions = []
        for ad in raw.get("actions", []):
            a = Action(
                action_id=ad["action_id"],
                tool=ad["tool"],
                params=ad.get("params", {}),
                description=ad.get("description", ""),
                status=ActionStatus(ad.get("status", "pending")),
                error=ad.get("error"),
            )
            actions.append(a)

        results = []
        for rd in raw.get("results", []):
            ad = rd["action"]
            a = Action(
                action_id=ad["action_id"],
                tool=ad["tool"],
                params=ad.get("params", {}),
                description=ad.get("description", ""),
                status=ActionStatus(ad.get("status", "success")),
                error=ad.get("error"),
            )
            results.append(ActionResult(action=a, result=rd.get("result", {})))

        return PipelineState(
            target=raw["target"],
            goal=raw.get("goal", ""),
            actions=actions,
            results=results,
            summary=raw.get("summary", ""),
        )

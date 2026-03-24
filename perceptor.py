"""
perceptor.py – The Perceptor component of VENUS_AI.

Aggregates raw tool results from an :class:`~models.PipelineState` into a
normalised, unified structure and provides helper query functions that the
Planner (LLM) or CLI can call.

Normalised surface model
------------------------
::

    {
      "target": str,
      "open_ports": [{"port": int, "protocol": str, "service": str, "version": str}],
      "os_guess": str,
      "tech_stack": [str],
      "endpoints": [{"url": str, "status": int, "interesting": bool}],
      "findings": [{"title": str, "severity": str, "url": str, "remediation": str}],
    }
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from models import PipelineState, Severity


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _extract_ports(results: list[dict]) -> tuple[list[dict], str]:
    """Pull open-port and OS data from any nmap results."""
    open_ports: list[dict] = []
    os_guess = ""
    for r in results:
        for p in r.get("ports", []):
            if p.get("state") == "open":
                open_ports.append({
                    "port":     p["number"],
                    "protocol": p["protocol"],
                    "service":  p["service"],
                    "version":  p.get("version", ""),
                })
        if not os_guess and r.get("os_guess"):
            os_guess = r["os_guess"]
    return open_ports, os_guess


def _extract_endpoints(results: list[dict]) -> list[dict]:
    """Pull endpoint list from dirsearch results."""
    endpoints: list[dict] = []
    for r in results:
        for e in r.get("endpoints", []):
            endpoints.append({
                "url":         e["url"],
                "status":      e["status_code"],
                "content_type": e.get("content_type", ""),
                "interesting": e.get("interesting", False),
            })
    return endpoints


def _extract_findings(results: list[dict]) -> list[dict]:
    """Pull vulnerability findings from nuclei results."""
    findings: list[dict] = []
    for r in results:
        for f in r.get("findings", []):
            findings.append({
                "title":       f["title"],
                "severity":    f["severity"],
                "template_id": f.get("template_id", ""),
                "url":         f["url"],
                "description": f.get("description", ""),
                "remediation": f.get("remediation", ""),
            })
    return findings


def _infer_tech_stack(
    ports: list[dict],
    endpoints: list[dict],
) -> list[str]:
    """Heuristically derive a technology stack list."""
    tech: set[str] = set()
    for p in ports:
        svc = p.get("service", "").lower()
        ver = p.get("version", "").lower()
        if "ssh" in svc:
            tech.add("OpenSSH")
        if "mysql" in svc or "mysql" in ver:
            tech.add("MySQL")
        if "apache" in ver:
            tech.add("Apache httpd")
        if "nginx" in ver:
            tech.add("nginx")
        if "iis" in ver:
            tech.add("Microsoft IIS")
    for e in endpoints:
        url = e.get("url", "").lower()
        if "phpmyadmin" in url:
            tech.add("phpMyAdmin")
        if ".php" in url:
            tech.add("PHP")
        if ".asp" in url or ".aspx" in url:
            tech.add("ASP.NET")
        if "wp-" in url or "wordpress" in url:
            tech.add("WordPress")
    return sorted(tech)


# ---------------------------------------------------------------------------
# Perceptor class
# ---------------------------------------------------------------------------

class Perceptor:
    """
    Aggregates and analyses results stored in a :class:`PipelineState`.

    Usage
    -----
    ::

        perc = Perceptor(state)
        surface = perc.normalise()
        high_plus = perc.findings_by_severity(["critical", "high"])
        attack_hints = perc.interesting_attack_surface()
    """

    def __init__(self, state: PipelineState) -> None:
        self._state = state
        self._surface: dict[str, Any] | None = None

    # ------------------------------------------------------------------
    # Primary normalisation
    # ------------------------------------------------------------------

    def normalise(self) -> dict[str, Any]:
        """
        Build and cache the unified surface model from all action results.

        Returns a JSON-serialisable ``dict`` (see module docstring).
        """
        if self._surface is not None:
            return self._surface

        nmap_results: list[dict]      = []
        dirsearch_results: list[dict] = []
        nuclei_results: list[dict]    = []

        for ar in self._state.results:
            tool = ar.action.tool
            res  = ar.result
            if not res:
                continue
            if tool == "run_nmap":
                nmap_results.append(res)
            elif tool == "run_dirsearch":
                dirsearch_results.append(res)
            elif tool == "run_nuclei":
                nuclei_results.append(res)

        open_ports, os_guess = _extract_ports(nmap_results)
        endpoints            = _extract_endpoints(dirsearch_results)
        findings             = _extract_findings(nuclei_results)
        tech_stack           = _infer_tech_stack(open_ports, endpoints)

        self._surface = {
            "target":     self._state.target,
            "os_guess":   os_guess,
            "open_ports": open_ports,
            "tech_stack": tech_stack,
            "endpoints":  endpoints,
            "findings":   findings,
        }
        return self._surface

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def findings_by_severity(
        self,
        severities: list[str] | None = None,
    ) -> list[dict]:
        """
        Return findings filtered (and sorted) by severity.

        Parameters
        ----------
        severities:
            List of severity strings to include, e.g. ``["critical","high"]``.
            Pass ``None`` to return all findings sorted by severity.
        """
        _order = {s.value: i for i, s in enumerate(Severity)}
        surface = self.normalise()
        findings = surface["findings"]

        if severities:
            sev_set = {s.lower() for s in severities}
            findings = [f for f in findings if f["severity"] in sev_set]

        return sorted(findings, key=lambda f: _order.get(f["severity"], 99))

    def interesting_attack_surface(self) -> dict[str, Any]:
        """
        Return a distilled view of the most noteworthy attack surface items.

        Includes:
        * Interesting endpoints (admin panels, exposed files, …)
        * Critical / High findings
        * Inferred tech stack
        """
        surface = self.normalise()
        return {
            "target":          surface["target"],
            "tech_stack":      surface["tech_stack"],
            "interesting_endpoints": [
                e for e in surface["endpoints"] if e.get("interesting")
            ],
            "high_severity_findings": self.findings_by_severity(
                ["critical", "high"]
            ),
        }

    def stats(self) -> dict[str, Any]:
        """Return quick statistics (port count, endpoint count, findings per severity)."""
        surface = self.normalise()
        by_sev: dict[str, int] = defaultdict(int)
        for f in surface["findings"]:
            by_sev[f["severity"]] += 1

        return {
            "open_port_count": len(surface["open_ports"]),
            "endpoint_count":  len(surface["endpoints"]),
            "finding_counts":  dict(by_sev),
        }

    def plain_text_report(self) -> str:
        """
        Generate a human-readable text report suitable for the CLI ``report`` command.
        """
        surface = self.normalise()
        lines: list[str] = []

        lines.append("=" * 60)
        lines.append(f"  VENUS_AI RECONNAISSANCE REPORT")
        lines.append(f"  Target : {surface['target']}")
        if surface["os_guess"]:
            lines.append(f"  OS     : {surface['os_guess']}")
        lines.append("=" * 60)

        # Ports
        lines.append("\n[+] OPEN PORTS")
        if surface["open_ports"]:
            for p in surface["open_ports"]:
                ver = f"  ({p['version']})" if p["version"] else ""
                lines.append(f"    {p['port']}/{p['protocol']:<4}  {p['service']}{ver}")
        else:
            lines.append("    (none found)")

        # Tech stack
        lines.append("\n[+] TECH STACK")
        if surface["tech_stack"]:
            for t in surface["tech_stack"]:
                lines.append(f"    • {t}")
        else:
            lines.append("    (not detected)")

        # Endpoints
        lines.append("\n[+] DISCOVERED ENDPOINTS")
        for e in surface["endpoints"]:
            flag = " ★" if e["interesting"] else ""
            lines.append(f"    [{e['status']}] {e['url']}{flag}")

        # Findings
        lines.append("\n[+] VULNERABILITY FINDINGS")
        _sev_icon = {
            "critical": "[CRIT]",
            "high":     "[HIGH]",
            "medium":   "[MED] ",
            "low":      "[LOW] ",
            "info":     "[INFO]",
        }
        for f in self.findings_by_severity():
            icon = _sev_icon.get(f["severity"], "[???]")
            lines.append(f"    {icon} {f['title']}")
            lines.append(f"           URL : {f['url']}")
            lines.append(f"           Fix : {f['remediation']}")
            lines.append("")

        lines.append("=" * 60)
        st = self.stats()
        lines.append(
            f"  Ports: {st['open_port_count']}  "
            f"Endpoints: {st['endpoint_count']}  "
            f"Findings: {sum(st['finding_counts'].values())}"
        )
        lines.append("=" * 60)
        return "\n".join(lines)

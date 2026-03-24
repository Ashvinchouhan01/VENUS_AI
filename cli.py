"""
cli.py – VENUS_AI command-line interface.

Entry points
------------
venus interactive                              – interactive REPL
venus scenario basic-web --target <url>       – run a pre-defined scenario
venus report --target <url>                   – print report from saved session

Design note
-----------
``rich`` is used for pretty output when available; the code falls back to
plain ``print`` gracefully, so the tool runs on a stock Kali install even
before extras are installed.
"""

from __future__ import annotations

import argparse
import sys
import textwrap
from pathlib import Path

# Optional rich import
try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.table import Table
    from rich import print as rprint
    _RICH = True
    console = Console()
except ImportError:
    _RICH = False
    console = None  # type: ignore[assignment]

from executor  import Executor
from models    import PipelineState
from perceptor import Perceptor
from planner   import LLMAgent

# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------

SCENARIOS: dict[str, list[str]] = {
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
        "run_vuln_scan_cves",
    ],
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

BANNER = r"""
 __   __ _____ _   _ _   _ _____     _    ___
 \ \ / /| ____| \ | | | | |  ___|   / \  |_ _|
  \ V / |  _| |  \| | | | | |_     / _ \  | |
   | |  | |___| |\  | |_| |  _|   / ___ \ | |
   |_|  |_____|_| \_|\___/|_|    /_/   \_\___|

  AI-Assisted Penetration Testing Orchestrator
  [ Educational / Authorised Use Only ]
"""


def _print(msg: str, style: str = "") -> None:
    if _RICH:
        console.print(msg, style=style or None)
    else:
        print(msg)


def _print_banner() -> None:
    if _RICH:
        console.print(Panel(BANNER, style="bold green", expand=False))
    else:
        print(BANNER)


def _print_report(report_text: str) -> None:
    if _RICH:
        console.print(Markdown(f"```\n{report_text}\n```"))
    else:
        print(report_text)


def _print_summary(summary: str) -> None:
    if _RICH:
        console.print(Markdown(summary))
    else:
        print(summary)


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

def cmd_scenario(target: str, scenario_name: str, verbose: bool) -> None:
    """Run a named pre-defined scenario against *target*."""
    if scenario_name not in SCENARIOS:
        _print(
            f"[!] Unknown scenario '{scenario_name}'. "
            f"Available: {', '.join(SCENARIOS)}",
            style="red",
        )
        sys.exit(1)

    _print_banner()
    _print(f"[*] Scenario  : {scenario_name}", style="cyan")
    _print(f"[*] Target    : {target}", style="cyan")

    # Build state from fixed scenario action list
    from planner import _ACTION_REGISTRY  # noqa: PLC0415

    action_ids = SCENARIOS[scenario_name]
    agent      = LLMAgent()
    executor   = Executor()

    state = PipelineState(
        target=target,
        goal=f"scenario:{scenario_name}",
    )

    # Resolve actions from registry (same helper the Planner uses)
    from models import Action  # noqa: PLC0415
    for aid in action_ids:
        if aid in _ACTION_REGISTRY:
            tool, params, desc = _ACTION_REGISTRY[aid]
            state.actions.append(
                Action(
                    action_id=aid,
                    tool=tool,
                    params={**params, "target": target},
                    description=desc,
                )
            )

    _print(f"\n[*] Actions planned: {len(state.actions)}")
    for a in state.actions:
        _print(f"    → {a.action_id}  ({a.description})", style="dim")

    _print("\n[*] Executing …\n")
    state = executor.run_pipeline(state)

    # Perceptor analysis
    perc    = Perceptor(state)
    surface = perc.normalise()

    if verbose:
        import json
        _print(json.dumps(surface, indent=2))

    # LLM summary
    _print("\n[*] Requesting LLM summary …\n")
    state.summary = agent.summarize(state)
    _print_summary(state.summary)

    # Plain text report
    _print("\n" + perc.plain_text_report())

    _print(
        f"\n[✓] Session saved to: sessions/{target.replace('/', '_')}",
        style="green",
    )


def cmd_report(target: str) -> None:
    """Load a saved session and print its report."""
    executor = Executor()
    state    = executor.load_state(target)

    if state is None:
        _print(
            f"[!] No session found for '{target}'. "
            "Run a scenario first.",
            style="red",
        )
        sys.exit(1)

    _print_banner()
    perc = Perceptor(state)
    _print(perc.plain_text_report())

    if state.summary:
        _print("\n── LLM Summary ──\n")
        _print_summary(state.summary)


def cmd_interactive() -> None:
    """Launch the interactive REPL."""
    _print_banner()
    agent    = LLMAgent()
    executor = Executor()
    history: list[dict] = []   # future: pass to LLM for context

    _print(
        "VENUS_AI interactive mode. Type 'help' for commands, 'exit' to quit.\n",
        style="bold",
    )

    _HELP = textwrap.dedent("""\
        Commands:
          recon <target>          – Plan & run fast recon (nmap + dirsearch)
          scenario <name> <target>– Run a named scenario  (basic-web / recon / full)
          report <target>         – Print report for a saved session
          plan <goal> <target>    – Ask the LLM to plan actions (dry-run)
          help                    – Show this message
          exit / quit             – Exit VENUS_AI
    """)

    while True:
        try:
            if _RICH:
                raw = console.input("[bold green]venus>[/bold green] ").strip()
            else:
                raw = input("venus> ").strip()
        except (EOFError, KeyboardInterrupt):
            _print("\n[*] Goodbye.", style="dim")
            break

        if not raw:
            continue

        parts = raw.split()
        cmd   = parts[0].lower()

        if cmd in ("exit", "quit"):
            _print("[*] Goodbye.", style="dim")
            break

        elif cmd == "help":
            _print(_HELP)

        elif cmd == "recon" and len(parts) >= 2:
            target = parts[1]
            state  = PipelineState(target=target, goal="recon")
            state.actions = agent.plan_actions(state)
            _print(f"\n[*] Planned {len(state.actions)} actions for '{target}'")
            state = executor.run_pipeline(state)
            state.summary = agent.summarize(state)
            _print_summary(state.summary)
            _print(Perceptor(state).plain_text_report() if _RICH else
                   Perceptor(state).plain_text_report())

        elif cmd == "scenario" and len(parts) >= 3:
            cmd_scenario(target=parts[2], scenario_name=parts[1], verbose=False)

        elif cmd == "report" and len(parts) >= 2:
            cmd_report(parts[1])

        elif cmd == "plan" and len(parts) >= 3:
            goal   = parts[1]
            target = parts[2]
            state  = PipelineState(target=target, goal=goal)
            actions = agent.plan_actions(state)
            _print(f"\n[*] LLM plan for '{goal}' on '{target}':")
            for a in actions:
                _print(f"    {a.action_id}  →  {a.tool}({a.params})")

        else:
            _print(f"[!] Unrecognised command: '{raw}'. Type 'help'.", style="yellow")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="venus",
        description="VENUS_AI – AI-assisted penetration testing orchestrator",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # interactive
    sub.add_parser("interactive", help="Open the interactive REPL")

    # scenario
    sc = sub.add_parser("scenario", help="Run a pre-defined scenario")
    sc.add_argument(
        "name",
        choices=list(SCENARIOS.keys()),
        help="Scenario name",
    )
    sc.add_argument("--target", required=True, help="Target URL or IP")
    sc.add_argument("--verbose", "-v", action="store_true",
                    help="Dump normalised surface as JSON")

    # report
    rp = sub.add_parser("report", help="Print report from stored session")
    rp.add_argument("--target", required=True, help="Target URL or IP")

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args   = parser.parse_args(argv)

    if args.command == "interactive":
        cmd_interactive()
    elif args.command == "scenario":
        cmd_scenario(
            target=args.target,
            scenario_name=args.name,
            verbose=args.verbose,
        )
    elif args.command == "report":
        cmd_report(target=args.target)


if __name__ == "__main__":
    main()

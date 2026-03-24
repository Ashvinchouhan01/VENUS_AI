"""
example_run.py – End-to-end demonstration of the VENUS_AI pipeline.

Run with:
    python example_run.py

No network access required – all tool calls are simulated.
"""

from __future__ import annotations

import json
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from executor  import Executor
from models    import PipelineState
from perceptor import Perceptor
from planner   import LLMAgent, _ACTION_REGISTRY
from models    import Action


def run_demo(target: str = "https://example.com") -> None:
    print("=" * 60)
    print("  VENUS_AI – Full Basic-Web Scenario Demo")
    print(f"  Target: {target}")
    print("=" * 60)

    # ------------------------------------------------------------------ #
    # 1. PLANNER – ask the LLM to generate an action plan                 #
    # ------------------------------------------------------------------ #
    print("\n[1] PLANNER – generating action plan …")

    agent = LLMAgent()   # uses MockLLMBackend by default
    state = PipelineState(target=target, goal="basic-web")
    state.actions = agent.plan_actions(state)

    print(f"    LLM returned {len(state.actions)} actions:")
    for a in state.actions:
        print(f"      • {a.action_id:<24} tool={a.tool}  params={a.params}")

    # ------------------------------------------------------------------ #
    # 2. EXECUTOR – run each action and persist results                   #
    # ------------------------------------------------------------------ #
    print("\n[2] EXECUTOR – running pipeline …")

    executor = Executor(sessions_dir="sessions")
    state    = executor.run_pipeline(state)

    for ar in state.results:
        status = ar.action.status.value.upper()
        print(f"    [{status:^8}] {ar.action.action_id}")

    # ------------------------------------------------------------------ #
    # 3. PERCEPTOR – normalise and query results                          #
    # ------------------------------------------------------------------ #
    print("\n[3] PERCEPTOR – normalising findings …")

    perc    = Perceptor(state)
    surface = perc.normalise()

    print("\n    --- Normalised Surface (JSON excerpt) ---")
    print(json.dumps({
        "target":     surface["target"],
        "os_guess":   surface["os_guess"],
        "tech_stack": surface["tech_stack"],
        "open_port_count": len(surface["open_ports"]),
        "endpoint_count":  len(surface["endpoints"]),
        "finding_count":   len(surface["findings"]),
    }, indent=4))

    print("\n    --- Interesting Attack Surface ---")
    attack = perc.interesting_attack_surface()
    for e in attack["interesting_endpoints"]:
        print(f"      ★ [{e['status']}] {e['url']}")
    for f in attack["high_severity_findings"]:
        print(f"      ⚠  [{f['severity'].upper()}] {f['title']}")

    # ------------------------------------------------------------------ #
    # 4. LLM SUMMARY                                                      #
    # ------------------------------------------------------------------ #
    print("\n[4] LLM SUMMARY (mock)")
    state.summary = agent.summarize(state)
    print(state.summary)

    # ------------------------------------------------------------------ #
    # 5. PLAIN TEXT REPORT                                                #
    # ------------------------------------------------------------------ #
    print("\n[5] PLAIN TEXT REPORT")
    print(perc.plain_text_report())

    # ------------------------------------------------------------------ #
    # 6. Stats                                                            #
    # ------------------------------------------------------------------ #
    print("[6] QUICK STATS")
    print(json.dumps(perc.stats(), indent=4))

    print("\n[✓] Demo complete. Session persisted under ./sessions/")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    run_demo(target)

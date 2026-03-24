# VENUS_AI

> **AI-Assisted Penetration Testing Orchestrator**
> Educational / Authorised-use-only framework. All tool calls are **simulated** by default.

---

## Architecture – Planner / Executor / Perceptor (PEP)

```
 User goal (natural language)
        │
        ▼
┌───────────────┐
│   PLANNER     │  LLMAgent.plan_actions(state)
│  planner.py   │  → list[Action]
└───────┬───────┘
        │ Action list
        ▼
┌───────────────┐
│   EXECUTOR    │  Executor.run_pipeline(state)
│  executor.py  │  run_nmap / run_dirsearch / run_nuclei
│               │  → PipelineState (results persisted to sessions/)
└───────┬───────┘
        │ PipelineState
        ▼
┌───────────────┐
│   PERCEPTOR   │  Perceptor(state).normalise()
│  perceptor.py │  → unified surface model
│               │  → plain_text_report / findings_by_severity / …
└───────────────┘
```

### Module map

| File | Role |
|------|------|
| `models.py`    | Shared dataclasses: `Action`, `PipelineState`, `NmapResult`, etc. |
| `planner.py`   | `LLMAgent` + `LLMBackend` abstraction (mock shipped, real pluggable) |
| `executor.py`  | Tool wrappers (`run_nmap`, `run_dirsearch`, `run_nuclei`) + `Executor` |
| `perceptor.py` | Aggregation, normalisation, query helpers, text report |
| `cli.py`       | `argparse`-based CLI commands |
| `venus_cli.py` | Thin entry-point wrapper |

---

## Quick Start

```bash
# Requirements: Python 3.11+ (optional: pip install rich)
cd venus_ai

# End-to-end demo (no network needed)
python example_run.py

# CLI – run basic-web scenario
python venus_cli.py scenario basic-web --target https://example.com

# CLI – print saved report
python venus_cli.py report --target https://example.com

# CLI – interactive REPL
python venus_cli.py interactive
```

---

## CLI Reference

### `venus scenario <name> --target <url>`

Runs a pre-defined sequence of tools.

| Scenario | Tools run |
|----------|-----------|
| `basic-web` | nmap fast → dirsearch → nuclei http |
| `recon` | nmap fast → dirsearch |
| `full` | nmap fast+deep → dirsearch → nuclei http+cves |

### `venus report --target <url>`

Reads the saved session under `sessions/<target>/state.json` and prints
a formatted text report.

### `venus interactive`

Opens a REPL. Supported commands inside:

```
recon <target>
scenario <name> <target>
report <target>
plan <goal> <target>      # dry-run: shows planned actions only
help
exit
```

---

## Replacing Mock Tool Calls with Real Tools

Each tool function in `executor.py` is a standalone Python function.
Replace its body with a `subprocess.run` call:

```python
# executor.py
import subprocess, json

def run_nmap(target: str, profile: str = "fast", **_) -> dict:
    flags = "-T4 --top-ports 1000" if profile == "fast" else "-A -p-"
    proc = subprocess.run(
        ["nmap", *flags.split(), "-oJ", "-", target],
        capture_output=True, text=True, timeout=300,
    )
    # parse nmap JSON output into NmapResult …
    raw = json.loads(proc.stdout)
    # … map to NmapResult dataclass and return .to_dict()
```

The Perceptor and report layer require **no changes** as long as you keep
the same dict schema returned by `NmapResult.to_dict()`.

---

## Replacing the Mock LLM with a Real Provider

Implement `LLMBackend` in `planner.py`:

```python
# planner.py – drop-in Anthropic backend
import anthropic

class AnthropicLLMBackend(LLMBackend):
    def __init__(self, model: str = "claude-opus-4-20250514") -> None:
        self._client = anthropic.Anthropic()   # reads ANTHROPIC_API_KEY
        self._model  = model

    def complete(self, system: str, user: str) -> str:
        msg = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return msg.content[0].text
```

Then pass it to `LLMAgent`:

```python
agent = LLMAgent(backend=AnthropicLLMBackend())
```

That's all — the rest of the pipeline is unchanged.

---

## Session Storage

Results are stored as JSON under `sessions/<safe_target>/`:

```
sessions/
  https___example.com/
    run_nmap_fast.json
    run_dir_enum.json
    run_vuln_scan_http.json
    state.json            ← full PipelineState
```

---

## Legal Notice

This tool is intended **solely for authorised security testing and education**.
Never use it against systems you do not have explicit written permission to test.

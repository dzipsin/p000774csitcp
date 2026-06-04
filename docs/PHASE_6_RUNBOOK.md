# Phase 6 — Evaluation Staircase Ablation

Procedure for measuring how each capability the agent added contributes
to triage quality. Run as a staircase: each row adds one component to
the prior row. The recall / F1 delta column tells the story.

| # | Step           | Model        | agent.mode    | auto_enrichment | custom XSS rules in Suricata |
|---|----------------|--------------|----------------|------------------|------------------------------|
| 1 | `baseline`     | llama3.2:3b  | single_shot   | false            | off                          |
| 2 | `model_swap`   | qwen2.5:3b   | single_shot   | false            | off                          |
| 3 | `react`        | qwen2.5:3b   | react         | false            | off                          |
| 4 | `enrich`       | qwen2.5:3b   | react         | true             | off                          |
| 5 | `custom_rules` | qwen2.5:3b   | react         | true             | on                           |

3 reps per config × 5 configs = 15 evaluation runs. Each run takes
~10–15 min depending on model speed + LLM latency. Plan ~2.5–3 hours
total operator time.

## Before you start

- Take a Kali VM snapshot. You will toggle Suricata config (custom rules
  on / off) between configs 4 and 5 — snapshot lets you roll back if
  anything misbehaves.
- Pull both Ollama models on the demo host:
  ```powershell
  ollama pull llama3.2
  ollama pull qwen2.5:3b
  ```
- Make sure `eval_results/` exists and is writable.
- Optionally clear stale results from previous campaigns to keep the
  combined report uncluttered:
  ```powershell
  Get-ChildItem eval_results\p6_*.* | Remove-Item
  ```

## Per-config procedure

For each of the 5 configurations below, repeat this loop **3 times**
(reps are aggregated by the combined-report generator):

### Step A — set `app.config` to the config's values

Edit `app.config`:

```toml
[model.ollama]
model_name = "<llama3.2 | qwen2.5:3b>"

[analysis]
include_lab_context = true        # leave as-is

[agent]
mode             = "<single_shot | react>"
auto_enrichment  = <true | false>
```

### Step B — Suricata custom rules on or off (only changes between configs 4 and 5)

```bash
# Inside the Kali VM
# OFF (configs 1-4):
sudo sed -i '/- xss_alerts.rules/d' /etc/suricata/suricata.yaml
sudo systemctl restart suricata

# ON (config 5 only):
sudo sh -c 'grep -q "xss_alerts.rules" /etc/suricata/suricata.yaml || \
    sed -i "/rule-files:/a\\  - xss_alerts.rules" /etc/suricata/suricata.yaml'
sudo systemctl restart suricata
```

Verify the right state with:
```bash
sudo grep "xss_alerts.rules" /etc/suricata/suricata.yaml
```

### Step C — restart the app on the host

```powershell
# Stop the previously running app (Ctrl+C in its terminal).
# Then in a fresh terminal:
.venv\Scripts\Activate.ps1
$env:EVE_LOG_PATH = "C:/Projects/soc-triage/eve.json"
python src\app.py
```

Watch the startup banner. Confirm the model, agent mode, and
auto_enrichment line read what you set in app.config.

### Step D — run the evaluation harness with the matching config-dim tag

In a SECOND terminal (leave the app running):

```powershell
.venv\Scripts\Activate.ps1
python -m src.evaluation.run_evaluation `
    --label "p6_<step>_rep<N>" `
    --repeats 1 `
    --config-dim '{\"step\":\"<step>\",\"model\":\"<model>\",\"agent_mode\":\"<mode>\",\"auto_enrichment\":<true|false>,\"custom_xss_rules\":<true|false>}'
```

Replace `<step>`, `<model>`, `<mode>`, `<N>`, and the boolean flags to
match the row from the staircase table.

The `--label` prefix `p6_<step>_` lets the combined-report generator
filter and group results across all reps.

### Step E — wait, verify, then move on

The harness will exit when it finishes (typically 10–15 min). On exit
you'll have two new files in `eval_results/`:

```
p6_<step>_rep<N>_<timestamp>_raw.json     # machine-readable
p6_<step>_rep<N>_<timestamp>_report.md    # markdown summary of the run
```

Quickly open the report.md to confirm metrics look sane (not all zeros,
not all errors). If you see something obviously wrong, debug before
moving on rather than salvaging later.

Repeat steps A–E for **3 reps of the SAME config**, then move to the
next config in the staircase (step A again with new values).

## After all 15 runs — generate the combined report

```powershell
python -m src.evaluation.run_combined_report `
    --indir eval_results `
    --label-prefix "p6_" `
    --order "baseline,model_swap,react,enrich,custom_rules" `
    --out eval_results/p6_combined_report.md
```

Output: `eval_results/p6_combined_report.md` — a single markdown table
plus per-step detail. The `ΔF1` column on each row shows how much that
step added to the F1 score versus the previous step (positive = the
component improved triage quality).

## What the staircase tells you

The ΔF1 column is the marker-facing summary of "what did each piece
contribute." Interpret like:

| Step             | What its ΔF1 measures                                          |
|------------------|---------------------------------------------------------------|
| `model_swap`     | The improvement from using a better local model               |
| `react`          | The improvement from agentic tool use over single-shot LLM    |
| `enrich`         | The improvement from hybrid auto-enrichment (Option F)        |
| `custom_rules`   | The recall improvement from teammate-authored Suricata rules  |

Negative deltas are honest data — they mean that component did not help
in this lab + workload. Report them as-is; don't hide them.

## Troubleshooting

- **Run aborts with `Dashboard not reachable`** — the app on the host
  isn't running, or the port is different. Confirm `python src\app.py`
  is alive.
- **All scenarios `no_detection`** — Suricata isn't seeing traffic, or
  alerts aren't reaching the host eve.json. Check the tail-bridge
  inside Kali.
- **Many `classification_errors`** — the LLM is failing to parse
  responses. Check `python src\app.py` console for ReActAgent parse
  failures. Common cause: small model adherence drift in long ReAct
  loops. If pervasive, consider increasing `max_retries_on_parse_fail`
  in code.
- **`--config-dim` rejected as invalid JSON** — PowerShell often eats
  inner double quotes. Either use single quotes around the whole arg
  and double-quotes inside (PowerShell), or backslash-escape
  consistently as shown in step D above.
- **Combined report shows "no runs matched"** — runs were saved
  without `--config-dim` so they have no `step` field. Re-run with the
  flag, or rename old runs to match the step-prefix fallback (e.g.
  `mv p6_run1_raw.json p6_baseline_run1_raw.json`).

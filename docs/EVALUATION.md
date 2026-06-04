# Evaluation Staircase Ablation

Procedure for measuring how each capability contributes to triage quality. Each row in the staircase adds one component to the previous; the F1 delta between rows attributes quality to specific design choices.

| # | Step | Model | `agent.mode` | `auto_enrichment` | Custom Suricata rules |
|---|------|-------|--------------|-------------------|-----------------------|
| 1 | `baseline` | llama3.2:3b | single_shot | false | off |
| 2 | `model_swap` | qwen2.5:3b | single_shot | false | off |
| 3 | `react` | qwen2.5:3b | react | false | off |
| 4 | `enrich` | qwen2.5:3b | react | true | off |
| 5 | `custom_rules` | qwen2.5:3b | react | true | on |

3 reps per config * 5 configs = 15 runs. Each run takes ~10-15 minutes. Total ~2.5-3 hours.

---

## Before Starting

Pull both Ollama models:

```bash
ollama pull llama3.2
ollama pull qwen2.5:3b
```

Ensure `eval_results/` exists and is writable.

---

## Per-Config Procedure

Repeat steps A-E **3 times** per configuration, then move to the next.

### Step A - Set `app.config`

```toml
[model.ollama]
model_name = "<llama3.2 | qwen2.5:3b>"

[agent]
mode            = "<single_shot | react>"
auto_enrichment = <true | false>
```

### Step B - Toggle Suricata custom rules (only changes between configs 4 and 5)

```bash
# OFF (configs 1-4):
sudo sed -i '/- xss_alerts.rules/d' /etc/suricata/suricata.yaml
sudo sed -i '/- sqli_alerts.rules/d' /etc/suricata/suricata.yaml
sudo systemctl restart suricata

# ON (config 5 only):
sudo sh -c 'grep -q "xss_alerts.rules" /etc/suricata/suricata.yaml || \
    sed -i "/rule-files:/a\\  - xss_alerts.rules" /etc/suricata/suricata.yaml'
sudo sh -c 'grep -q "sqli_alerts.rules" /etc/suricata/suricata.yaml || \
    sed -i "/rule-files:/a\\  - sqli_alerts.rules" /etc/suricata/suricata.yaml'
sudo systemctl restart suricata
```

Verify:
```bash
sudo grep -E "xss_alerts|sqli_alerts" /etc/suricata/suricata.yaml
```

### Step C - Restart the app

```bash
source .venv/bin/activate
python src/app.py
```

Confirm the startup banner shows the correct model, agent mode, and auto_enrichment value.

### Step D - Run the evaluation harness

In a second terminal:

```bash
source .venv/bin/activate
python -m src.evaluation.run_evaluation \
    --label "p6_<step>_rep<N>" \
    --repeats 1 \
    --config-dim '{"step":"<step>","model":"<model>","agent_mode":"<mode>","auto_enrichment":<true|false>,"custom_rules":<true|false>}'
```

### Step E - Verify and move on

Each run produces two files in `eval_results/`:

```
p6_<step>_rep<N>_<timestamp>_raw.json
p6_<step>_rep<N>_<timestamp>_report.md
```

Check `report.md` for sanity (non-zero metrics, no mass classification errors) before proceeding to the next rep.

---

## After All 15 Runs - Combined Report

```bash
python -m src.evaluation.run_combined_report \
    --indir eval_results \
    --label-prefix "p6_" \
    --order "baseline,model_swap,react,enrich,custom_rules" \
    --out eval_results/p6_combined_report.md
```

Output: `eval_results/p6_combined_report.md` - staircase table with `dF1` column showing each component's contribution. Negative deltas are honest data; report them as-is.

| Step | What its `dF1` measures |
|------|------------------------|
| `model_swap` | Improvement from a better local model |
| `react` | Improvement from agentic tool use vs single-shot |
| `enrich` | Improvement from hybrid auto-enrichment |
| `custom_rules` | Recall improvement from custom Suricata rules |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Dashboard not reachable` | Confirm `python src/app.py` is running on port 5000 |
| All scenarios `no_detection` | Suricata isn't seeing traffic or `eve.json` bridge is down; check Suricata status |
| Many `classification_errors` | LLM parse failures; check app console for ReActAgent errors |
| `--config-dim` rejected as invalid JSON | Escape inner double quotes consistently; on bash use single outer quotes |
| Combined report "no runs matched" | Runs saved without `--config-dim`; re-run with the flag |

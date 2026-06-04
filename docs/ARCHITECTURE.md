# Architecture and Workflow

A walkthrough of how the system works end to end, with the team's hand-drawn
system overview diagram embedded.

> New to the project? Read this doc first, then `docs/HANDOFF.md` (the written
> context: what's done, what's left, why), then `README.md` (setup).

---

## 1. System overview

The whole flow, in one paragraph. Someone attacks a deliberately-broken web
app inside a virtual machine. Suricata flags the attack and writes a log
line. The Python app on the host reads that log, asks a local AI what to
make of it, and shows the result on a dashboard.

![System overview](../system-overview.png)

### Reading the diagram by colour

**Red zone (Kali VM).** This is the lab. The attacker (your browser, or
curl) hits DVWA, a deliberately vulnerable web app running in a Docker
container on port 8080. Suricata sits on the Docker bridge with our custom
XSS and SQLi rules loaded, watching every HTTP request go by. When a request
matches one of our rules, Suricata writes one line into `eve.json`.

**Yellow zone (bridge).** There is no network connection between the VM and
the host. Instead, a `tail -F` inside the VM streams every new line of
`eve.json` into a folder that VirtualBox shares with the host, so the host
reads alerts just by reading a file.

**Blue zone (host).** This is the actual triage system, written in Python.

`log_monitor` tails the mirrored file and parses each JSON line into an
`AlertRecord`. It hands that record to `incident_manager`, which groups
records by source IP into incidents using a 2-minute sliding window. If new
alerts from the same attacker keep arriving, the incident stays open and
grows. After 3 seconds of silence (the debounce), `incident_manager`
triggers `report_generator` to actually build the report. That way, bursts
of alerts collapse into one regeneration instead of five.

`report_generator` does two things. First, it loops over each alert in the
incident and calls `react_agent` for the Stage 1 classification.
`react_agent` talks to Ollama running the qwen2.5:3b model locally. Once
every alert has a verdict, `report_generator` makes its own Stage 2 LLM
call to write the cross-alert incident narrative. The finished report goes
into `SQLite reports.db` and out through `web_server` (Flask + Socket.IO)
to the analyst's browser.

One thing worth pointing out in the diagram: raw alerts also stream
directly from `log_monitor` to `web_server` (the long dashed arrow along
the bottom). The analyst sees alerts the moment they arrive, without
waiting for the AI to finish. The full report follows a few seconds later,
once the debounce expires and the two LLM stages run.

### Why a VM and a host instead of one box

DVWA is supposed to be broken. Running it on the same machine as your
normal files is a bad idea: if the container ever gets out, that's your
laptop. The VM is throwaway. Snapshot it, break it, roll back. The triage
system runs on the host because qwen2.5:3b wants more RAM than you would
give a throwaway VM, and reinstalling a 2 GB model every time you reset
the lab gets old fast.

### Why a file as the bridge

Suricata already writes `eve.json` whether anyone is reading it or not.
So instead of opening a port on the VM or running a forwarding daemon,
we just expose that file to the host through a VirtualBox shared folder
and tail it. No network protocol to design, no service to keep alive. The
VM stays closed except for that one file path.

### Why a local LLM (Ollama + qwen2.5:3b)

Two reasons. Nothing leaves the machine: no API keys, no costs, no data
shipped to a third party. And qwen2.5:3b is small enough to run quickly
on a laptop (a few seconds per classification) but big enough to handle
structured output and tool calls reliably. 3B parameters is roughly the
floor where ReAct-style tool use starts working; smaller models tend to
skip tool calls or emit broken JSON.

### What the AI actually does (two distinct jobs)

`react_agent` (Stage 1) classifies each alert individually. Before it even
asks the model anything, it auto-runs three lookups: prior alerts from this
IP, environment context for the IP (is this one of ours?), and stats for
this attack type over the last 24 hours. Those results get baked into the
prompt. Then the model gives a verdict: real attack or noise, severity,
attack type, confidence.

`report_generator` (Stage 2) runs once per incident regeneration, after
every alert has been classified. This is where the plain-English narrative,
the MITRE tactic, and the suggested response actions come from. Stage 2
also has deterministic post-processing on top of the LLM output: a MITRE
override that scans the signature and URL for credential keywords (so
credential-extraction attacks get tagged Credential Access, not Initial
Access), and a three-layer suggestion filter that strips generic platitudes
and drops suggestions that contradict the enrichment data (like "block
internal IP" when the IP is one of ours).

### Arrow conventions in the diagram

- Solid arrows are calls or data being passed from one box to another. The
  label tells you what is moving: `AlertRecord`, `incident snapshot`,
  `classify(alert)`, `Stage 1 LLM call`, and so on.
- Dashed arrows are async events with nobody waiting for a reply. There
  are two of them, both going into `web_server` for WebSocket broadcast:
  `raw_alert event` from `log_monitor` (the long one along the bottom)
  and `report_ready event` from `report_generator` (the one above the
  SQLite box).

---

## 2. What the LLM actually does

The "AI" in this project is a small open-source language model called
`qwen2.5:3b`. It runs locally on the analyst's computer through a tool
called Ollama. Nothing leaves the machine. No API costs. No internet
dependency.

3 billion parameters is small by 2026 standards. Frontier models
(Claude, GPT-4, Gemini) are 100+ billion. So we are honest about the
trade-off: this model is fast and cheap and runs on a laptop, but it
is not as smart as a frontier model. We work around its weak spots
with rule-based Python in the right places (see "How we work around
the model's limits" below).

### The two jobs the LLM does

The model has exactly two jobs in this pipeline. Both are wrapped by
deterministic code that builds the prompt, calls the model, parses
the response, validates it against a schema, and falls back to
something sensible if the response is broken.

**Job 1: classify one alert.** Given an alert (signature, source IP,
URL, severity tier), decide whether it is a real attack or a false
alarm. Pick a severity (critical / high / low). Write a one-line
rationale. Pick one of a fixed set of response recommendations
(block source IP, escalate to Tier-2, continue monitoring).

Before the model sees the alert, the system already runs three
lookups for it: prior alerts from the same source IP, the role of
that IP in the lab (internal database? attacker simulator? unknown?),
and recent statistics for this attack type. Those results are baked
into the prompt as if the model had asked for them itself. The model
can ask for additional lookups if it wants (that is the "ReAct
loop"), but in practice it usually does not need to.

**Job 2: write the incident summary.** Once every alert in an
incident has been classified, the system calls the model one more
time, this time with all the classified alerts together. The model
writes the multi-paragraph incident narrative, picks a MITRE tactic,
lists the attack vectors, names the data that might have been
exposed, and suggests response actions in plain English.

Both jobs run the same model with the same settings. The only thing
that changes is the prompt and what the surrounding Python code does
with the response.

### What the LLM is NOT doing

It helps to be specific about what is NOT the model's responsibility.
The LLM is one component, not the whole system.

- It does NOT receive alerts directly. Python reads alerts from a
  file, parses them, groups them into incidents, and only then hands
  one (or many) to the model.
- It does NOT call any APIs other than the three lookup tools we
  explicitly hand it. No general network access, no file writes, no
  shell.
- It does NOT remember anything between alerts. Each classification
  is fresh. State lives in SQLite and the in-memory incident manager,
  not in the model.
- It does NOT generate the dashboard, the WebSocket messages, the
  incident report JSON shape, or the suggested-actions list shape.
  Those are deterministic Python working from the model's output.
- It does NOT decide when to raise alerts. Suricata does that. The
  model only sees alerts that Suricata already flagged.

### How we work around the model's limits

A 3B parameter model is not perfect. Concrete things we have observed
and built code to compensate for:

- **It sometimes mislabels the attack type.** A SQLi alert can come
  back as `attack_type = "Other"` even when the model's own rationale
  describes it as a UNION SELECT. Fix: deterministic code in
  `models.extract_attack_type()` resolves the type from the signature
  ID range first (our custom rules sit on known SID ranges) and only
  falls back to the model.
- **It sometimes picks the wrong MITRE tactic.** Credential
  extraction via SQLi can get labelled "Reconnaissance" or "Initial
  Access" instead of "Credential Access". Fix: a rule-based override
  in `report_generator.py` checks the signature and the URL for
  credential keywords. If the model was already right, the override
  does nothing. If the model was wrong, it gets corrected.
- **It sometimes suggests dangerous things.** "Block 172.18.0.2 at
  the firewall" when 172.18.0.2 is our own internal database server.
  Fix: a three-layer suggestion filter drops generic platitudes,
  drops suggestions that contradict the enrichment data (you cannot
  block your own infrastructure), and drops near-duplicates of what
  the rule-based suggestion generator already produced.
- **It sometimes hallucinates numbers.** Without help it might claim
  "47 prior alerts from this IP" when the real count is 6. Fix: the
  three lookup tools feed real counts into the prompt so the model is
  reading numbers, not inventing them.
- **It can output broken JSON or invalid XML.** Fix: the parser is
  strict, the schema validator is strict, the loop retries once, and
  a single-shot fallback path catches the rest. Parse-failure rate is
  tracked as an evaluation metric.
- **It varies slightly between runs even at `temperature = 0.0`.**
  The structured fields (classification, severity, attack type) stay
  stable across reruns. The free-text fields (rationale, narrative)
  drift in wording. This is a known property of 3B models, not a bug
  to fix.

### Limitations you should be aware of as a user

Beyond the workarounds above, a few things that are not "bugs we
could fix" but real limits of the approach:

- **Confidence scores are LLM-generated.** They are advisory, not
  ground truth. A 0.8 confidence does not mean 80% accurate; it
  means the model felt 80%-ish about its own answer.
- **The model has not been fine-tuned for SOC work.** It is a
  general-purpose model that we prompt carefully. A fine-tuned
  model would likely classify more accurately, but the project is
  scoped to off-the-shelf qwen2.5:3b for reproducibility.
- **Latency is real.** Each alert classification takes a few seconds
  on a laptop GPU, ten to fifteen seconds on CPU. Incident
  regeneration (when a new alert lands in an existing incident)
  re-runs the LLM, so bursts of alerts cause noticeable lag before
  the dashboard updates. The 3-second debounce in
  `incident_manager` collapses bursts into one regeneration to help.
- **The model cannot tell you when it is wrong.** It will produce a
  confident-sounding answer even when the input is ambiguous. The
  evaluation harness measures accuracy against ground truth so we
  have an external check, but in the live demo the marker has to
  trust the output. This is why the rule-based overrides + filters
  matter: they enforce sanity at the boundary.
- **The model has a context window.** Long incident histories or
  very large alert payloads can overflow it. Not a problem at lab
  volumes (incidents top out at a few dozen alerts) but worth
  flagging if scaling.
- **It is not a substitute for a human Tier-2 analyst.** Every
  AI Suggestion list ends up in front of an analyst who decides
  whether to action it. The model triages, the human acts.

### Why a local LLM at all

We chose a local LLM rather than a frontier API for three reasons.
None of them is "local is technically better" — a bigger model would
classify more accurately. They are:

1. **Cost.** No API bills. The marker can run the demo on their own
   laptop without anyone topping up credits.
2. **Privacy.** Nothing leaves the machine. For a SOC tool that is
   processing what could be real attack data, this matters.
3. **Reproducibility.** The model file is pinned. Two years from now
   `ollama pull qwen2.5:3b` returns the same weights. Frontier APIs
   change behind the scenes; what works in May 2026 might behave
   differently in May 2027.

To swap in a bigger model (a 7B or 13B local model, or a frontier
API) you change `model_name` (or `provider`) in `app.config` and
probably get better classification accuracy out of the box. The
pipeline is provider-agnostic by design.

---

## Where to go next

| You want to... | Read |
|---|---|
| See what's done, what's left, branch state | `docs/HANDOFF.md` |
| Understand the agent design decisions | `docs/AGENT_DESIGN.md` |
| Run the evaluation campaign | `docs/PHASE_6_RUNBOOK.md` |
| Understand the SQLite layer | `docs/PHASE_10_SQLITE.md` |
| Deploy or modify the Suricata rules | `lab/suricata/README.md` |
| Set up the lab from a clean machine | top-level `README.md` |

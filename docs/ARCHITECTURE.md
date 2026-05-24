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

## Where to go next

| You want to... | Read |
|---|---|
| See what's done, what's left, branch state | `docs/HANDOFF.md` |
| Understand the agent design decisions | `docs/AGENT_DESIGN.md` |
| Run the evaluation campaign | `docs/PHASE_6_RUNBOOK.md` |
| Understand the SQLite layer | `docs/PHASE_10_SQLITE.md` |
| Deploy or modify the Suricata rules | `lab/suricata/README.md` |
| Set up the lab from a clean machine | top-level `README.md` |

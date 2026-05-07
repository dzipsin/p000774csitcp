"""
attack_runner.py - Fires labeled HTTP requests at DVWA for evaluation.

For each Scenario, an HTTP request is sent to DVWA. A marker query parameter
(`eval_id=<scenario.eval_id>`) is added so the result collector can later
correlate reports/alerts back to the scenario that triggered them.

DVWA requires a session cookie (and sometimes a CSRF token). We:
  1. Log in once at start, capture the PHPSESSID cookie
  2. Set security=low via the security cookie
  3. Reuse the session across all scenarios

This module uses only the stdlib (urllib) so no extra dependencies are needed
on the Windows host beyond what the app already installs.
"""

from __future__ import annotations

import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.cookiejar import CookieJar, DefaultCookiePolicy
from typing import Dict, Optional

from .scenarios import Scenario

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result from firing a single scenario
# ---------------------------------------------------------------------------

@dataclass
class FireResult:
    eval_id: str
    sent_at_epoch: float
    sent_at_iso: str           # for human-readable logs
    http_status: int
    url_fired: str             # full URL including eval_id, as sent
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# DVWA client
# ---------------------------------------------------------------------------

class DVWAClient:
    """Lightweight HTTP client that maintains a DVWA session.

    Not a general-purpose HTTP library — just enough to fire the scenarios
    we care about without pulling `requests` as a new dependency.
    """

    def __init__(
        self,
        base_url: str = "http://192.168.56.101:8080",
        username: str = "admin",
        password: str = "password",
        security_level: str = "low",
        request_timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.security_level = security_level
        self.request_timeout = request_timeout

        self._jar = CookieJar()
        # Use a liberal cookie policy: by default, CookieJar rejects cookies
        # set with domain=.192.168.56.101 (leading dot on an IP) for "third
        # party" reasons. DomainLiberal accepts them, which is what we need
        # for DVWA behind an IP address.
        self._jar.set_policy(DefaultCookiePolicy(
            strict_ns_domain=DefaultCookiePolicy.DomainLiberal,
        ))
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar)
        )
        # Pretend to be a real browser so DVWA doesn't behave oddly
        self._opener.addheaders = [(
            "User-Agent",
            "Mozilla/5.0 (SOC-Triage-Evaluator)"
        )]

    # ------------------------------------------------------------------
    # Session setup
    # ------------------------------------------------------------------

    def login(self) -> None:
        """Obtain a session cookie and set security=low.

        Raises:
            RuntimeError if login fails (wrong creds, DVWA not reachable, etc.)
        """
        # Step 1: GET /login.php to obtain the initial PHPSESSID and the
        # user_token field (DVWA uses a CSRF-like nonce even on login).
        login_url = f"{self.base_url}/login.php"
        try:
            with self._opener.open(login_url, timeout=self.request_timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as e:
            raise RuntimeError(
                f"Could not reach DVWA at {login_url}: {e}. "
                "Verify the VM is running, DVWA is up, and the URL is correct."
            )

        user_token = _extract_user_token(body)

        # Step 2: POST credentials
        post_data = {
            "username": self.username,
            "password": self.password,
            "Login": "Login",
        }
        if user_token:
            post_data["user_token"] = user_token

        encoded = urllib.parse.urlencode(post_data).encode("utf-8")
        req = urllib.request.Request(login_url, data=encoded, method="POST")
        try:
            with self._opener.open(req, timeout=self.request_timeout) as resp:
                final_url = resp.geturl()
        except urllib.error.URLError as e:
            raise RuntimeError(f"Login POST to DVWA failed: {e}")

        # Successful login redirects away from /login.php
        if "login.php" in final_url:
            raise RuntimeError(
                f"DVWA login apparently failed (still on login page). "
                f"Credentials: {self.username}/****. "
                f"If this is the first run on a new DVWA install, visit the "
                f"DVWA setup page manually first: {self.base_url}/setup.php"
            )

        # Step 3: Set security level via the security page
        self._set_security_level()

        log.info("DVWA login successful (security=%s)", self.security_level)

    def _set_security_level(self) -> None:
        """POST to /security.php to set the security level cookie/session var."""
        url = f"{self.base_url}/security.php"
        try:
            with self._opener.open(url, timeout=self.request_timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as e:
            log.warning("Could not load security page: %s", e)
            return

        token = _extract_user_token(body)

        post_data = {
            "security": self.security_level,
            "seclev_submit": "Submit",
        }
        if token:
            post_data["user_token"] = token

        encoded = urllib.parse.urlencode(post_data).encode("utf-8")
        req = urllib.request.Request(url, data=encoded, method="POST")
        try:
            self._opener.open(req, timeout=self.request_timeout).read()
        except urllib.error.URLError as e:
            log.warning("Failed to set security level: %s", e)

    # ------------------------------------------------------------------
    # Firing scenarios
    # ------------------------------------------------------------------

    def fire(self, scenario: Scenario) -> FireResult:
        """Send the HTTP request for a scenario, with the eval_id marker injected.

        Returns a FireResult with the timing and HTTP status.
        Never raises on HTTP-level failures — records them in `error` so the
        evaluation run can continue.
        """
        sent_at = time.time()
        sent_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(sent_at))

        try:
            url, status = self._fire_scenario(scenario)
            return FireResult(
                eval_id=scenario.eval_id,
                sent_at_epoch=sent_at,
                sent_at_iso=sent_iso,
                http_status=status,
                url_fired=url,
            )
        except Exception as e:
            log.warning("Scenario %s fire failed: %s", scenario.eval_id, e)
            return FireResult(
                eval_id=scenario.eval_id,
                sent_at_epoch=sent_at,
                sent_at_iso=sent_iso,
                http_status=0,
                url_fired="",
                error=f"{type(e).__name__}: {e}",
            )

    def _fire_scenario(self, scenario: Scenario):
        """Low-level: builds and sends the request. May raise."""
        params = dict(scenario.query_params)
        # Inject the eval_id marker so we can correlate later.
        # We use a dedicated param name unlikely to collide with real DVWA inputs.
        params["eval_id"] = scenario.eval_id

        full_url = f"{self.base_url}{scenario.path}"
        if scenario.method.upper() == "GET":
            query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
            full_url = f"{full_url}?{query}" if query else full_url
            req = urllib.request.Request(full_url, method="GET")
        elif scenario.method.upper() == "POST":
            body = dict(scenario.form_data or {})
            body["eval_id"] = scenario.eval_id
            encoded = urllib.parse.urlencode(body).encode("utf-8")
            # For POSTs, also add eval_id to URL so it shows up in HTTP URL
            # that Suricata captures (Suricata logs GET query strings readily;
            # POST bodies are harder to correlate).
            query = urllib.parse.urlencode({"eval_id": scenario.eval_id})
            full_url = f"{full_url}?{query}"
            req = urllib.request.Request(full_url, data=encoded, method="POST")
        else:
            raise ValueError(f"Unsupported method: {scenario.method}")

        try:
            with self._opener.open(req, timeout=self.request_timeout) as resp:
                return (full_url, resp.status)
        except urllib.error.HTTPError as e:
            # DVWA returns non-200 on some payloads; that's not a failure for
            # our purposes — we still want to record what we fired.
            return (full_url, e.code)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_user_token(html: str) -> Optional[str]:
    """Extract the DVWA user_token hidden field from an HTML response.

    DVWA embeds a CSRF-like token in forms. It's present on login and security
    pages. Different DVWA versions use single OR double quotes in the attribute
    (observed: `value='...'` on login page, `value="..."` on security page),
    so we handle both.

    Returns None if not found (some DVWA versions don't use tokens at all).
    """
    import re
    # Match name='user_token' OR name="user_token" followed by value attribute
    # in either quote style, with flexible whitespace.
    pattern = re.compile(
        r"""name\s*=\s*['"]user_token['"]\s+value\s*=\s*['"]([^'"]+)['"]""",
        re.IGNORECASE,
    )
    m = pattern.search(html)
    if m:
        return m.group(1)

    # Try the reverse attribute order too (value before name)
    pattern2 = re.compile(
        r"""value\s*=\s*['"]([^'"]+)['"]\s+name\s*=\s*['"]user_token['"]""",
        re.IGNORECASE,
    )
    m2 = pattern2.search(html)
    if m2:
        return m2.group(1)

    return None
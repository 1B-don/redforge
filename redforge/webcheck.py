"""Single-request HTTP(S) header inspection of scoped literal-IP targets.

No redirects, no proxy environment, no hostname resolution, and no crawling.
"""
from __future__ import annotations
import http.client
import ipaddress
import json
import ssl
import threading
from typing import Callable
from pathlib import Path
from .core import connect, require_target, add_finding, evidence_file, audit, now

SECURITY_HEADERS = ["content-security-policy", "x-content-type-options", "referrer-policy", "strict-transport-security"]


def _cookie_observations(raw_headers: list[tuple[str, str]], tls: bool) -> list[dict]:
    observations = []
    for key, value in raw_headers:
        if key.lower() != "set-cookie" or len(observations) >= 32:
            continue
        parts = [part.strip() for part in value.split(";")]
        name = parts[0].split("=", 1)[0][:100]
        attributes = {part.split("=", 1)[0].strip().lower():
                      part.split("=", 1)[1].strip().lower() if "=" in part else True
                      for part in parts[1:]}
        same_site = attributes.get("samesite")
        issues = []
        if tls and "secure" not in attributes:
            issues.append("Secure flag absent on HTTPS response")
        if same_site == "none" and "secure" not in attributes:
            issues.append("SameSite=None without Secure")
        observations.append({"name": name, "secure": "secure" in attributes,
                             "http_only": "httponly" in attributes,
                             "same_site": same_site if isinstance(same_site, str) else None,
                             "issues": issues})
    return observations


def check(root: Path, target: str, port: int = 80, tls: bool = False, cancel: threading.Event | None = None, on_connection: Callable[[http.client.HTTPConnection], None] | None = None) -> dict:
    if not 1 <= port <= 65535:
        raise ValueError("Invalid TCP port")
    with connect(root) as db:
        target = require_target(db, target)
        # http.client does not automatically follow redirects or honor proxy variables.
        cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
        conn = cls(target, port, timeout=8, context=ssl.create_default_context()) if tls else cls(target, port, timeout=8)
        if on_connection is not None:
            on_connection(conn)
        try:
            if cancel is not None and cancel.is_set():
                raise InterruptedError("HTTP inspection cancelled")
            conn.request("HEAD", "/", headers={"User-Agent": "RedForge/0.16 authorized-assessment"})
            response = conn.getresponse()
            response.read(4096)
            raw_headers = response.getheaders()
            cookies = _cookie_observations(raw_headers, tls)
            headers = {k.lower(): v for k, v in raw_headers if k.lower() != "set-cookie"}
            if cookies:
                headers["set-cookie"] = f"{len(cookies)} cookie(s); values redacted"
            result = {"at": now(), "target": target, "port": port, "tls": tls,
                      "status": response.status, "headers": headers, "cookies": cookies,
                      "missing_security_headers": [h for h in SECURITY_HEADERS if h not in headers and (tls or h != "strict-transport-security")]}
        finally:
            conn.close()
        if cancel is not None and cancel.is_set():
            raise InterruptedError("HTTP inspection cancelled")
        ev = evidence_file(root, "http", json.dumps(result, indent=2))
        for name in result["missing_security_headers"]:
            add_finding(db, target, f"Header not observed: {name}", "low", "This header was absent from the HEAD response. Confirm applicability and verify with additional testing; absence alone does not prove exploitability.", ev)
        for cookie in cookies:
            if cookie["issues"]:
                add_finding(db, target, f"Cookie flag observation: {cookie['name']}", "low",
                            "; ".join(cookie["issues"]) + ". Based on one HEAD response; validate cookie purpose and behavior.", ev)
        audit(db, "web_check", json.dumps({"target": target, "port": port, "evidence": ev}))
        return result

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
            conn.request("HEAD", "/", headers={"User-Agent": "RedForge/0.1 authorized-assessment"})
            response = conn.getresponse()
            response.read(4096)
            headers = {k.lower(): v for k, v in response.getheaders()}
            result = {"at": now(), "target": target, "port": port, "tls": tls, "status": response.status, "headers": headers, "missing_security_headers": [h for h in SECURITY_HEADERS if h not in headers and (tls or h != "strict-transport-security")]}
        finally:
            conn.close()
        if cancel is not None and cancel.is_set():
            raise InterruptedError("HTTP inspection cancelled")
        ev = evidence_file(root, "http", json.dumps(result, indent=2))
        for name in result["missing_security_headers"]:
            add_finding(db, target, f"Header not observed: {name}", "low", "This header was absent from the HEAD response. Confirm applicability and verify with additional testing; absence alone does not prove exploitability.", ev)
        audit(db, "web_check", json.dumps({"target": target, "port": port, "evidence": ev}))
        return result

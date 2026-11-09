"""Read-only platform and engagement readiness checks."""
from __future__ import annotations

import platform
import shutil
import sys
from pathlib import Path

from .core import connect
from .overview import overview


def diagnose(root: Path) -> dict:
    system = platform.system()
    checks = [
        {"name": "Platform", "status": "ready" if system in {"Darwin", "Linux"} else "unsupported",
         "detail": "macOS" if system == "Darwin" else system},
        {"name": "Python", "status": "ready" if sys.version_info >= (3, 10) else "unsupported",
         "detail": platform.python_version()},
        {"name": "Nmap", "status": "ready" if shutil.which("nmap") else "setup",
         "detail": shutil.which("nmap") or ("Install with brew install nmap" if system == "Darwin" else "Install Nmap for TCP scans")},
    ]
    try:
        with connect(root):
            pass
        state = overview(root)
    except (ValueError, OSError):
        state = None
    checks.append({"name": "Engagement", "status": "ready" if state else "setup",
                   "detail": state["engagement"] if state else "Create or open an engagement"})
    if state:
        checks.extend([
            {"name": "Authorization", "status": "ready" if state["authorized"] else "setup",
             "detail": "Operator acknowledgement recorded" if state["authorized"] else "Confirm written permission"},
            {"name": "Active scope", "status": "ready" if state["scope_active"] else "setup",
             "detail": f"{state['scope_active']} active, {state['scope_expired']} expired"},
            {"name": "Assessment history", "status": "ready" if state["runs"] else "setup",
             "detail": f"{state['runs']} saved automatic run(s)"},
        ])
    if system == "Darwin":
        checks.append({"name": "Wi-Fi mode switching", "status": "unsupported",
                       "detail": "Linux-only adapter control"})
    elif system == "Linux":
        ready = bool(shutil.which("iw") and shutil.which("pkexec") and shutil.which("ip"))
        checks.append({"name": "Wi-Fi mode switching", "status": "ready" if ready else "optional",
                       "detail": "Requires iw, pkexec, iproute2, and compatible hardware"})
    if not state:
        next_step = {"screen": "engagement", "label": "Create or open an engagement"}
    elif not state["host_audits"]:
        next_step = {"screen": "hostaudit", "label": "Run a read-only local host audit"}
    elif not state["scope_active"]:
        next_step = {"screen": "scope", "label": "Add an authorized target to scope"}
    elif not state["authorized"]:
        next_step = {"screen": "engagement", "label": "Record authorization acknowledgement"}
    elif not shutil.which("nmap"):
        next_step = {"screen": "readiness", "label": "Install Nmap for TCP scanning"}
    elif not state["runs"]:
        next_step = {"screen": "auto", "label": "Run your first automatic assessment"}
    elif state["findings"].get("unreviewed", 0):
        next_step = {"screen": "findings", "label": "Review unreviewed findings"}
    else:
        next_step = {"screen": "reports", "label": "Export the engagement report"}
    return {"platform": system, "checks": checks, "engagement": state, "next_step": next_step}

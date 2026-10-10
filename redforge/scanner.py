"""Bounded Nmap TCP enumeration and safe XML parsing."""
from __future__ import annotations
import json
import shutil
import subprocess
import threading
import time
import os
import signal
from pathlib import Path
from defusedxml import ElementTree
from .core import connect, require_target, audit, evidence_file, add_finding, now


def scan(root: Path, target: str, ports: str = "22,80,443,8080", cancel: threading.Event | None = None) -> dict:
    # Restrict the user-controlled port expression to a bounded, explicit list.
    tokens = ports.split(",")
    if not tokens or len(tokens) > 32:
        raise ValueError("Specify 1–32 comma-separated TCP ports.")
    try:
        nums = [int(t) for t in tokens]
    except ValueError as exc:
        raise ValueError("Ports must be integers, not ranges or Nmap options.") from exc
    if any(not 1 <= p <= 65535 for p in nums):
        raise ValueError("Port must be between 1 and 65535.")
    with connect(root) as db:
        target = require_target(db, target)
        if not shutil.which("nmap"):
            raise ValueError("Nmap is missing. Install it with: sudo apt install nmap")
        cmd = ["nmap", "-sT", "-Pn", "-n", "--max-retries", "1", "--host-timeout", "90s", "-p", ",".join(map(str, sorted(set(nums)))), "-oX", "-", target]
        audit(db, "scan_start", json.dumps({"target": target, "ports": nums}))
        # A cancellable process group ensures Back/ESC actually stops Nmap.
        if cancel is not None and cancel.is_set():
            audit(db, "scan_cancelled", target)
            raise InterruptedError("Scan cancelled before starting")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, start_new_session=True)
        try:
            deadline = time.monotonic() + 105
            while proc.poll() is None:
                if cancel is not None and cancel.is_set():
                    audit(db, "scan_cancelled", target)
                    raise InterruptedError("Scan cancelled when leaving the assessment screen")
                if time.monotonic() > deadline:
                    audit(db, "scan_timeout", target)
                    raise TimeoutError("Scan exceeded 105-second time limit")
                time.sleep(0.1)
            stdout, stderr = proc.communicate()
        except (InterruptedError, TimeoutError):
            # Terminate descendants as well as the parent scanner process.
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.communicate()
            raise
        else:
            proc.stdout.close()
            proc.stderr.close()
        # stdout/stderr are local variables from communicate(); do not
        # reference them inside a class body (which raises NameError).
        if cancel is not None and cancel.is_set():
            audit(db, "scan_cancelled", target)
            raise InterruptedError("Scan cancelled before processing results")
        if proc.returncode != 0:
            audit(db, "scan_failed", stderr[:500])
            raise ValueError(f"Nmap failed: {stderr.strip()[:500]}")
        root_xml = ElementTree.fromstring(stdout)
        found = []
        for host in root_xml.findall("host"):
            for p in host.findall("./ports/port"):
                state = p.find("state")
                if state is not None and state.attrib.get("state") == "open":
                    service = p.find("service")
                    item = {"port": int(p.attrib["portid"]), "protocol": p.attrib.get("protocol", "tcp"), "service": service.attrib.get("name", "unknown") if service is not None else "unknown"}
                    found.append(item)
        result = {"at": now(), "target": target, "open_ports": found, "command": cmd[:-1] + ["<authorized-target>"]}
        ev = evidence_file(root, "tcp", json.dumps(result, indent=2))
        for item in found:
            add_finding(db, target, f"TCP port {item['port']} open", "info", f"Observed service: {item['service']}. An open port alone is not a vulnerability.", ev)
        audit(db, "scan_complete", json.dumps({"target": target, "open": len(found), "evidence": ev}))
        return result

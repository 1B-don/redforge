"""Bounded assessment of explicitly selected, authorized IP addresses."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from threading import Event

from .core import connect, require_target, audit, now
from .scanner import scan
from .sshcheck import inspect as inspect_ssh
from .tlscheck import inspect
from .webcheck import check
from .compare import save_run, compare_runs


def assess(root: Path, targets: list[str], ports: str = "22,80,443,8080,8443", cancel: Event | None = None) -> dict:
    if not targets or len(targets) > 16:
        raise ValueError("Specify 1–16 explicit IP targets.")
    canonical = []
    for target in targets:
        try:
            address = str(ipaddress.ip_address(target))
        except ValueError as exc:
            raise ValueError(f"Target must be a literal IP address: {target}") from exc
        if address not in canonical:
            canonical.append(address)
    # Validate every target before any network activity.
    with connect(root) as db:
        for target in canonical:
            require_target(db, target)
        audit(db, "auto_start", json.dumps({"targets": canonical, "ports": ports}))

    results = []
    for target in canonical:
        if cancel is not None and cancel.is_set():
            raise InterruptedError("Assessment cancelled")
        item = {"target": target, "open_ports": [], "scan_ok": False, "checks": [], "observations": {}, "errors": []}
        try:
            scanned = scan(root, target, ports, cancel=cancel)
            item["open_ports"] = scanned["open_ports"]
            item["scan_ok"] = True
        except (ValueError, OSError, TimeoutError) as exc:
            item["errors"].append(f"TCP scan: {exc}")
            results.append(item)
            continue
        for port in sorted({p["port"] for p in item["open_ports"]}):
            if cancel is not None and cancel.is_set():
                raise InterruptedError("Assessment cancelled")
            actions = []
            if port == 22:
                actions.append(("SSH banner", lambda p=port: inspect_ssh(root, target, p, cancel=cancel)))
            if port in (80, 8080):
                actions.append(("HTTP headers", lambda p=port: check(root, target, p, cancel=cancel)))
            if port in (443, 8443):
                actions.extend((("TLS", lambda p=port: inspect(root, target, p, cancel=cancel)),
                                ("HTTPS headers", lambda p=port: check(root, target, p, tls=True, cancel=cancel))))
            for label, action in actions:
                try:
                    observation = action()
                    item["checks"].append(f"{label} on {port}")
                    if label == "SSH banner":
                        item["observations"][f"ssh:{port}"] = observation.get("banner")
                    elif label == "TLS":
                        item["observations"][f"tls:{port}"] = {
                            "protocol": observation.get("protocol"),
                            "certificate_sha256": observation.get("peer_certificate_sha256")}
                        item["observations"][f"tls:{port}"]["certificate_not_after"] = observation.get("certificate_not_after")
                    else:
                        item["observations"][f"http:{port}"] = {
                            "status": observation.get("status"),
                            "missing_security_headers": observation.get("missing_security_headers"),
                            "cookies": observation.get("cookies", [])}
                except (ValueError, OSError, TimeoutError) as exc:
                    item["errors"].append(f"{label} on {port}: {exc}")
        results.append(item)
    summary = {"at": now(), "targets": results}
    summary["run_id"] = save_run(root, summary)
    summary["alerts"] = []
    try:
        comparison = compare_runs(root)
        if comparison["after"] == summary["run_id"]:
            summary["alerts"] = comparison["changes"]
    except ValueError:
        pass  # First run has no baseline.
    with connect(root) as db:
        if summary["alerts"]:
            audit(db, "change_alert", json.dumps({"run_id": summary["run_id"], "changes": summary["alerts"]}))
        audit(db, "auto_complete", json.dumps(summary))
    return summary

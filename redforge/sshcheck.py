"""Read one SSH identification banner from an authorized host."""
from __future__ import annotations

import json
import socket
from pathlib import Path
from threading import Event

from .core import connect, require_target, audit, evidence_file, add_finding, now


def inspect(root: Path, target: str, port: int = 22, cancel: Event | None = None) -> dict:
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    if cancel is not None and cancel.is_set():
        raise InterruptedError("SSH inspection cancelled")
    with connect(root) as db:
        target = require_target(db, target)
        audit(db, "ssh_start", json.dumps({"target": target, "port": port}))
        try:
            with socket.create_connection((target, port), timeout=5) as connection:
                connection.settimeout(5)
                # RFC 4253 permits pre-banner lines. Bound both lines and bytes.
                stream = connection.makefile("rb")
                banner = None
                for _ in range(6):
                    if cancel is not None and cancel.is_set():
                        raise InterruptedError("SSH inspection cancelled")
                    line = stream.readline(256)
                    if not line:
                        break
                    if line.startswith(b"SSH-"):
                        banner = line.rstrip(b"\r\n").decode("ascii", errors="replace")
                        break
                if banner is None:
                    raise ValueError("No SSH identification banner received")
        except (OSError, ValueError) as exc:
            audit(db, "ssh_failed", str(exc)[:300])
            raise ValueError(f"SSH inspection failed: {exc}") from exc
        if cancel is not None and cancel.is_set():
            raise InterruptedError("SSH inspection cancelled")
        protocol = banner.split("-", 2)[1] if "-" in banner else "unknown"
        result = {"at": now(), "target": target, "port": port, "banner": banner, "protocol": protocol}
        ev = evidence_file(root, "ssh", json.dumps(result, indent=2))
        audit(db, "ssh_complete", json.dumps({"target": target, "port": port, "evidence": ev}))
        if protocol == "1.5":
            add_finding(db, target, "Legacy SSH protocol advertised", "medium",
                        f"SSH-1.5 banner on TCP {port}; verify actual server configuration.", ev)
        return result

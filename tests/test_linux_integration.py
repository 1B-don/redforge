"""Real Linux smoke checks; enabled only in the dedicated CI job."""
import asyncio
import os
import platform
import shutil
import socket
from threading import Thread

import pytest

from redforge.core import initialize, connect, add_scope, authorize
from redforge.scanner import scan
from redforge.tui import RedForgeTUI, Home

pytestmark = pytest.mark.integration


@pytest.mark.skipif(platform.system() != "Linux" or os.getenv("REDFORGE_INTEGRATION") != "1" or not shutil.which("nmap"),
                    reason="requires Linux integration job with Nmap")
def test_real_loopback_tcp_scan(tmp_path):
    initialize(tmp_path, "Integration")
    with connect(tmp_path) as db:
        add_scope(db, "127.0.0.1/32", "Local integration test")
        authorize(db, True)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        result = scan(tmp_path, "127.0.0.1", str(port))
    assert port in [item["port"] for item in result["open_ports"]]


@pytest.mark.skipif(platform.system() != "Linux" or os.getenv("REDFORGE_INTEGRATION") != "1",
                    reason="requires Linux integration job")
def test_dashboard_opens_and_navigates(tmp_path):
    async def exercise():
        app = RedForgeTUI(tmp_path)
        async with app.run_test() as pilot:
            assert isinstance(app.screen, Home)
            await pilot.press("c")
            assert app.screen.title_text == "Automatic Assessment"
            await pilot.press("escape")
            assert isinstance(app.screen, Home)
    asyncio.run(exercise())

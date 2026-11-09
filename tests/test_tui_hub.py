import asyncio

from redforge.core import initialize
from redforge.tui import Home, HostAudit, Readiness, RedForgeTUI, ToolCatalog


def test_unified_hub_navigation(tmp_path):
    initialize(tmp_path, 'Hub test')

    async def exercise():
        app = RedForgeTUI(tmp_path)
        async with app.run_test() as pilot:
            assert isinstance(app.screen, Home)
            await pilot.press('d')
            assert isinstance(app.screen, Readiness)
            await pilot.press('escape')
            assert isinstance(app.screen, Home)
            await pilot.press('e')
            assert isinstance(app.screen, ToolCatalog)
            app.screen.query_one('#search').value = 'file integrity'
            await pilot.pause()
            assert len(app.screen.visible_tools) == 1
            await pilot.press('escape')
            await pilot.press('f')
            assert isinstance(app.screen, HostAudit)

    asyncio.run(exercise())

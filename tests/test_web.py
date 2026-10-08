"""Testes de web content discovery (helpers offline + um servidor efêmero local)."""
import asyncio

from aiohttp import web as aioweb

from gyntoolkit.web import COMMON_PATHS, _normalize_base, _parse_robots, web_discovery


def test_normalize_base_adds_scheme_and_slash():
    assert _normalize_base("example.com") == "http://example.com/"
    assert _normalize_base("https://x") == "https://x/"
    assert _normalize_base("http://x/") == "http://x/"


def test_parse_robots_extracts_paths_and_sitemaps():
    txt = (
        "# comment\n"
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Allow: /public\n"
        "Disallow: /admin\n"          # duplicado → dedup
        "Sitemap: http://x/sitemap.xml\n"
    )
    out = _parse_robots(txt)
    assert out["paths"] == ["/admin", "/public"]
    assert out["sitemaps"] == ["http://x/sitemap.xml"]


def test_common_paths_curated():
    assert "robots.txt" in COMMON_PATHS
    assert ".env" in COMMON_PATHS


async def _serve_and_scan():
    async def _robots(_):
        return aioweb.Response(text="Disallow: /secret\n")

    async def _admin(_):
        return aioweb.Response(text="admin area")

    async def _secret(_):
        return aioweb.Response(text="s")

    app = aioweb.Application()
    app.router.add_get("/robots.txt", _robots)
    app.router.add_get("/admin", _admin)
    app.router.add_get("/secret", _secret)
    runner = aioweb.AppRunner(app)
    await runner.setup()
    site = aioweb.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        return await web_discovery(f"http://127.0.0.1:{port}", workers=10)
    finally:
        await runner.cleanup()


def test_web_discovery_finds_known_and_robots_paths():
    res = asyncio.run(_serve_and_scan())
    paths = {f["path"] for f in res["found"]}
    assert res["robots"]["found"] is True
    assert "admin" in paths              # da wordlist embutida
    assert "robots.txt" in paths
    assert "secret" in paths             # descoberto via Disallow do robots
    # caminhos inexistentes (404) não entram
    assert all(f["status"] != 404 for f in res["found"])

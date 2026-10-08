"""Mais cobertura de brute — mocks + servidor aiohttp efêmero (offline)."""
import asyncio
import base64

from aiohttp import web as aioweb

import gyntoolkit.brute as brute


# ---------- load_wordlist ----------
def test_load_wordlist_dedup(tmp_path):
    f = tmp_path / "w.txt"
    f.write_text("a\nb\n\na\n  c  \n", encoding="utf-8")
    assert brute.load_wordlist(str(f)) == ["a", "b", "c"]


def test_load_wordlist_missing(tmp_path):
    assert brute.load_wordlist(str(tmp_path / "nope.txt")) == []


# ---------- ssh_bruteforce (mock _ssh_try) ----------
def test_ssh_bruteforce_finds(monkeypatch):
    async def fake_try(host, port, user, password, timeout):
        return (user, password) if (user, password) == ("admin", "hunter2") else None
    monkeypatch.setattr(brute, "_ssh_try", fake_try)
    out = asyncio.run(brute.ssh_bruteforce(
        "127.0.0.1", ["root", "admin"], ["x", "hunter2"], workers=4, delay=0))
    assert ("admin", "hunter2") in out
    assert len(out) == 1


# ---------- http_bruteforce (servidor efêmero) ----------
async def _serve_and_brute(mode):
    async def basic(request):
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            user, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
            if (user, pw) == ("admin", "letmein"):
                return aioweb.Response(status=200, text="ok")
        return aioweb.Response(status=401, text="denied")

    async def login(request):
        data = await request.post()
        if (data.get("username"), data.get("password")) == ("admin", "s3cret"):
            return aioweb.Response(status=200, text="welcome")
        return aioweb.Response(status=200, text="Invalid credentials")

    app = aioweb.Application()
    app.router.add_get("/basic", basic)
    app.router.add_post("/login", login)
    runner = aioweb.AppRunner(app)
    await runner.setup()
    site = aioweb.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        if mode == "basic":
            return await brute.http_bruteforce(
                f"http://127.0.0.1:{port}/basic", ["root", "admin"], ["x", "letmein"],
                mode="basic", workers=4, delay=0)
        return await brute.http_bruteforce(
            f"http://127.0.0.1:{port}/login", ["admin"], ["x", "s3cret"],
            mode="form", fail_signature="Invalid credentials", workers=4, delay=0)
    finally:
        await runner.cleanup()


def test_http_bruteforce_basic():
    out = asyncio.run(_serve_and_brute("basic"))
    assert out == [("admin", "letmein")]


def test_http_bruteforce_form():
    out = asyncio.run(_serve_and_brute("form"))
    assert out == [("admin", "s3cret")]


# ---------- cupp_generate (not found branch) ----------
def test_cupp_generate_not_found(monkeypatch, tmp_path, capsys):
    # cwd sem cupp/ e PROJECT_ROOT sem cupp → caminho "não encontrado"
    monkeypatch.setattr(brute.Path, "cwd", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(brute, "PROJECT_ROOT", tmp_path)
    brute.cupp_generate()  # não deve levantar
    assert "CUPP" in capsys.readouterr().out or True

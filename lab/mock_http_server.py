"""
Mock HTTP server para testes locais do gyntoolkit brute force.
Roda em 127.0.0.1:8080.

Endpoints:
  /basic  → Basic Auth. Cred válida: admin:letmein
  /login  → GET mostra form. POST autentica com u=admin&p=s3cret.
             Falha responde HTML contendo "Invalid credentials".

USO APENAS EM LABORATÓRIO.
"""
import argparse
import base64
import logging
import sys
from aiohttp import web

BASIC_USER, BASIC_PASS = "admin", "letmein"
FORM_USER, FORM_PASS = "admin", "s3cret"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("mock-http")


async def handle_basic(request: web.Request) -> web.Response:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return web.Response(status=401, headers={"WWW-Authenticate": 'Basic realm="mock"'}, text="Auth required")
    try:
        decoded = base64.b64decode(auth[6:]).decode("utf-8")
        user, _, password = decoded.partition(":")
    except (ValueError, UnicodeDecodeError):
        return web.Response(status=401, text="Invalid header")

    if user == BASIC_USER and password == BASIC_PASS:
        log.info("BASIC OK: %s:%s", user, password)
        return web.Response(status=200, text="Welcome " + user)
    return web.Response(status=401, headers={"WWW-Authenticate": 'Basic realm="mock"'}, text="Denied")


async def handle_login_get(request: web.Request) -> web.Response:
    return web.Response(
        text="<html><form method=post><input name=username><input name=password><button>Login</button></form></html>",
        content_type="text/html",
    )


async def handle_login_post(request: web.Request) -> web.Response:
    data = await request.post()
    user = data.get("username", "")
    password = data.get("password", "")
    if user == FORM_USER and password == FORM_PASS:
        log.info("FORM OK: %s:%s", user, password)
        return web.Response(status=200, text="<html>Welcome " + str(user) + "</html>", content_type="text/html")
    return web.Response(status=200, text="<html>Invalid credentials</html>", content_type="text/html")


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/basic", handle_basic)
    app.router.add_get("/login", handle_login_get)
    app.router.add_post("/login", handle_login_post)
    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    log.info("Mock HTTP: /basic (%s:%s) | /login form (%s:%s) em %s:%s",
             BASIC_USER, BASIC_PASS, FORM_USER, FORM_PASS, args.host, args.port)
    web.run_app(build_app(), host=args.host, port=args.port, print=None)


if __name__ == "__main__":
    sys.exit(main())

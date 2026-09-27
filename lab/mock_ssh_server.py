"""
Mock SSH server para testes locais do gyntoolkit brute force.
Roda em 127.0.0.1:2222. Credenciais válidas: admin:hunter2, root:toor.

USO APENAS EM LABORATÓRIO. Não expor em rede pública.
"""
import argparse
import logging
import socket
import sys
import threading
import paramiko

VALID_CREDS = {
    "admin": "hunter2",
    "root": "toor",
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("mock-ssh")


class MockSSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_auth_password(self, username: str, password: str) -> int:
        expected = VALID_CREDS.get(username)
        if expected and password == expected:
            log.info("AUTH OK: %s:%s", username, password)
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


def handle(client_sock, host_key):
    transport = paramiko.Transport(client_sock)
    transport.add_server_key(host_key)
    server = MockSSHServer()
    try:
        transport.start_server(server=server)
        chan = transport.accept(10)
        if chan is not None:
            chan.close()
    except paramiko.SSHException as e:
        log.debug("SSH negociação falhou: %s", e)
    finally:
        try:
            transport.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    args = parser.parse_args()

    host_key = paramiko.RSAKey.generate(2048)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(100)
    log.info("Mock SSH escutando em %s:%s (creds: %s)", args.host, args.port, VALID_CREDS)

    try:
        while True:
            client, addr = sock.accept()
            log.debug("Conexão de %s", addr)
            t = threading.Thread(target=handle, args=(client, host_key), daemon=True)
            t.start()
    except KeyboardInterrupt:
        log.info("Encerrando...")
    finally:
        sock.close()


if __name__ == "__main__":
    sys.exit(main())

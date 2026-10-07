"""
Automated E2E: starts mocks, attacks with gyntoolkit, validates creds, tears down.
Run from the project root: python lab/run_e2e.py
"""
import asyncio
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import gyntoolkit as g  # noqa: E402

USERS = ["admin", "root", "user", "guest", "test"]
PASSWORDS = ["123456", "password", "admin", "toor", "letmein", "hunter2", "s3cret", "qwerty"]

EXPECTED_SSH = {("admin", "hunter2"), ("root", "toor")}
EXPECTED_HTTP_BASIC = {("admin", "letmein")}
EXPECTED_HTTP_FORM = {("admin", "s3cret")}


def start_mock(name: str, script: str) -> subprocess.Popen:
    print(f"[E2E] Starting {name}...")
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "lab" / script)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc


async def run_tests() -> int:
    failures = 0

    # Teste 1: SSH brute
    print("\n[E2E] === SSH brute-force ===")
    ssh_results = await g.ssh_bruteforce(
        "127.0.0.1", USERS, PASSWORDS, port=2222, workers=5, delay=0.05, timeout=3,
    )
    ssh_set = set(ssh_results)
    if ssh_set == EXPECTED_SSH:
        print(f"[E2E] [OK] SSH PASS — found {ssh_set}")
    else:
        print(f"[E2E] [FAIL] SSH FAIL — expected {EXPECTED_SSH}, got {ssh_set}")
        failures += 1

    # Teste 2: HTTP basic
    print("\n[E2E] === HTTP basic-auth brute-force ===")
    http_basic = await g.http_bruteforce(
        "http://127.0.0.1:8080/basic", USERS, PASSWORDS,
        mode="basic", workers=8, delay=0.02, timeout=5,
    )
    http_basic_set = set(http_basic)
    if http_basic_set == EXPECTED_HTTP_BASIC:
        print(f"[E2E] [OK] HTTP basic PASS — found {http_basic_set}")
    else:
        print(f"[E2E] [FAIL] HTTP basic FAIL — expected {EXPECTED_HTTP_BASIC}, got {http_basic_set}")
        failures += 1

    # Teste 3: HTTP form
    print("\n[E2E] === HTTP form brute-force ===")
    http_form = await g.http_bruteforce(
        "http://127.0.0.1:8080/login", USERS, PASSWORDS,
        mode="form", user_field="username", pass_field="password",
        fail_signature="Invalid credentials", workers=8, delay=0.02, timeout=5,
    )
    http_form_set = set(http_form)
    if http_form_set == EXPECTED_HTTP_FORM:
        print(f"[E2E] [OK] HTTP form PASS — found {http_form_set}")
    else:
        print(f"[E2E] [FAIL] HTTP form FAIL — expected {EXPECTED_HTTP_FORM}, got {http_form_set}")
        failures += 1

    return failures


def main() -> int:
    ssh_proc = start_mock("SSH mock", "mock_ssh_server.py")
    http_proc = start_mock("HTTP mock", "mock_http_server.py")

    print("[E2E] Waiting 3s for servers to come up...")
    time.sleep(3)

    try:
        failures = asyncio.run(run_tests())
    finally:
        print("\n[E2E] Shutting down mocks...")
        for proc in (ssh_proc, http_proc):
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    if failures:
        print(f"\n[E2E] {failures} FAILURE(S). [FAIL]")
        return 1
    print("\n[E2E] ALL TESTS PASSED. [OK]")
    return 0


if __name__ == "__main__":
    sys.exit(main())

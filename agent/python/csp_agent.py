#!/usr/bin/env python3
"""
CSP Cyber Sim Platform — Python agent (Linux / macOS).

Caldera-style HTTP-polling agent. The agent:

  1. registers with the C2 using a one-time enrollment token,
  2. beacons every N seconds for tasks,
  3. executes each task via the executor named by the C2 (bash / sh / python3),
  4. POSTs the captured stdout / stderr / exit code back to the C2.

Safety guardrails:
  * The agent only runs commands sent by the C2 — but the C2 only queues
    commands that came verbatim from the catalog (server side is the source
    of truth). The agent does not parse arguments from the network.
  * Per-task timeout enforced locally (cap 60 s).
  * Output captured and truncated to 32 KB per stream.
  * Run on test endpoints you own / are authorized to test.

Usage:
    python3 csp_agent.py \\
        --c2 https://csp.example.com \\
        --enroll-token ent_xxx \\
        --label "lab-host-01"
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import platform as plat
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

AGENT_VERSION = "0.3.0-py"
DEFAULT_INTERVAL = 30
MAX_OUTPUT = 32 * 1024
MAX_TIMEOUT = 60
RUNNABLE_EXECUTORS = {"bash", "sh", "python3"}

log = logging.getLogger("csp.agent")


# ---------- HTTP helpers ----------
def _http(url: str, body: dict, headers: dict, timeout: int = 30) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("content-type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"http {exc.code}: {body}") from exc


# ---------- platform / discovery ----------
def detect_platform() -> str:
    sysname = plat.system().lower()
    if sysname == "darwin":
        return "macos"
    if sysname == "linux":
        return "linux"
    return sysname


def detect_internal_ip() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


# ---------- task execution ----------
def run_task(task: dict, default_timeout: int) -> dict:
    executor = task["executor"]
    command = task["command"]
    timeout = max(1, min(int(task.get("timeout_sec") or default_timeout), MAX_TIMEOUT))

    if executor not in RUNNABLE_EXECUTORS:
        return {
            "task_id": task["id"],
            "status": "error",
            "exit_code": -2,
            "duration_ms": 0,
            "stdout": "",
            "stderr": f"executor {executor!r} not runnable on this agent",
            "truncated": False,
        }

    if executor in ("bash", "sh"):
        argv = [executor, "-c", command]
    else:  # python3
        argv = ["python3", "-c", command]

    if shutil.which(argv[0]) is None:
        return {
            "task_id": task["id"],
            "status": "error",
            "exit_code": -3,
            "duration_ms": 0,
            "stdout": "",
            "stderr": f"executor binary {argv[0]!r} not present on host",
            "truncated": False,
        }

    started = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 — argv from C2-trusted catalog
            argv,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        truncated = len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT
        status = "done"
        exit_code = proc.returncode
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.monotonic() - started) * 1000)
        stdout = (exc.stdout or b"").decode("utf-8", errors="replace")
        stderr = (exc.stderr or b"").decode("utf-8", errors="replace") + f"\n[timeout after {timeout}s]"
        status = "timeout"
        exit_code = -9
        truncated = True
    except FileNotFoundError as exc:
        duration_ms = int((time.monotonic() - started) * 1000)
        stdout, stderr = "", str(exc)
        status, exit_code, truncated = "error", -3, False

    if task.get("cleanup"):
        try:
            subprocess.run(
                ["bash", "-c", task["cleanup"]],
                capture_output=True,
                timeout=10,
                check=False,
            )
        except Exception:  # noqa: BLE001
            pass  # cleanup failures are not fatal for the test result

    return {
        "task_id": task["id"],
        "status": status,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "stdout": stdout[:MAX_OUTPUT],
        "stderr": stderr[:MAX_OUTPUT],
        "truncated": truncated,
    }


# ---------- main loop ----------
def register(c2: str, enroll_token: str, label: str | None) -> dict:
    body = {
        "enroll_token": enroll_token,
        "hostname": label or socket.gethostname(),
        "platform": detect_platform(),
        "agent_version": AGENT_VERSION,
        "internal_ip": detect_internal_ip(),
    }
    return _http(f"{c2.rstrip('/')}/agent-c2/register", body, headers={})


def main() -> int:
    p = argparse.ArgumentParser(description="CSP Python agent")
    p.add_argument("--c2", required=True, help="C2 base URL, e.g. https://csp.example.com")
    p.add_argument("--enroll-token", help="one-time enrollment token (omit if --agent-id+--agent-secret provided)")
    p.add_argument("--agent-id", help="re-use a previously registered agent_id")
    p.add_argument("--agent-secret", help="agent_secret matching --agent-id")
    p.add_argument("--label", help="hostname label sent on register")
    p.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="beacon interval seconds")
    p.add_argument("--once", action="store_true", help="one beacon then exit (debugging)")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    c2 = args.c2.rstrip("/")
    if args.agent_id and args.agent_secret:
        agent_id, agent_secret = args.agent_id, args.agent_secret
        interval = args.interval
        log.info("re-using agent_id=%s", agent_id)
    elif args.enroll_token:
        log.info("registering with C2 %s ...", c2)
        try:
            reg = register(c2, args.enroll_token, args.label)
        except RuntimeError as exc:
            log.error("registration failed: %s", exc)
            return 2
        agent_id = reg["agent_id"]
        agent_secret = reg["agent_secret"]
        interval = int(reg.get("beacon_interval_sec", args.interval))
        log.info("registered agent_id=%s interval=%ss", agent_id, interval)
    else:
        log.error("provide either --enroll-token, or --agent-id + --agent-secret")
        return 2

    headers = {"x-agent-id": agent_id, "x-agent-secret": agent_secret}
    while True:
        try:
            log.debug("beacon...")
            resp = _http(f"{c2}/agent-c2/beacon", {}, headers)
            tasks = resp.get("tasks", [])
            if tasks:
                log.info("got %d task(s)", len(tasks))
            for t in tasks:
                log.info("running %s/%s (%s)", t["technique_id"], t["test_name"], t["executor"])
                result = run_task(t, default_timeout=int(t.get("timeout_sec") or 15))
                _http(f"{c2}/agent-c2/result", result, headers)
                log.info(" → status=%s exit=%s dur=%sms",
                         result["status"], result["exit_code"], result["duration_ms"])
        except RuntimeError as exc:
            log.error("c2 error: %s", exc)
        except KeyboardInterrupt:
            log.info("interrupted, exiting")
            return 0
        except Exception as exc:  # noqa: BLE001
            log.error("loop error: %s", exc)

        if args.once:
            return 0
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())

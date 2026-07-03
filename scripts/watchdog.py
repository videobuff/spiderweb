#!/usr/bin/env python3
"""
Watchdog for PA0ESH-3: alerts by email when
  1. dxspider.service is not active, or
  2. spiderweb.service (the web GUI, gunicorn) is not active, or
  3. the spot flow from DXSpider into the MySQL "dxcluster.spot" table has
     stalled (no new spot in FLOW_STALL_MINUTES minutes) while dxspider
     itself is still active.

Meant to run from cron every few minutes. Only emails when the set of
active problems changes (ok->problem, problem->ok, or the mix changes)
plus a repeat reminder every REMINDER_MINUTES while any problem persists,
so it won't spam on every run.
"""
import json
import smtplib
import subprocess
import time
from email.message import EmailMessage
from pathlib import Path

BASE = Path("/home/sysop/spider/spiderweb")
CONFIG_FILE = BASE / "cfg" / "config.json"
STATE_FILE = BASE / "data" / "watchdog_state.json"

FLOW_STALL_MINUTES = 15
REMINDER_MINUTES = 60


def load_config():
    with open(CONFIG_FILE) as f:
        return json.load(f)


def service_active(name: str) -> bool:
    r = subprocess.run(
        ["systemctl", "is-active", name],
        capture_output=True, text=True,
    )
    return r.stdout.strip() == "active"


def latest_spot_age_seconds(cfg) -> float | None:
    """Seconds since the newest row in dxcluster.spot, or None on query failure."""
    my = cfg["mysql"]
    cmd = [
        "mysql", "-h", my["host"], "-u", my["user"], f"-p{my['passwd']}",
        my["db"], "-N", "-e", "SELECT UNIX_TIMESTAMP() - MAX(time) FROM spot;",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return None
        return float(r.stdout.strip())
    except Exception:
        return None


def send_mail(cfg, subject: str, body: str) -> bool:
    mail = cfg.get("watchdog_smtp", {}) or {}
    to_addr = mail.get("notify")
    if not mail or not to_addr:
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = mail.get("sender", mail.get("user"))
    msg["To"] = to_addr
    msg.set_content(body)
    try:
        with smtplib.SMTP(mail["host"], mail.get("port", 587), timeout=20) as s:
            if mail.get("use_tls", True):
                s.starttls()
            if mail.get("user") and mail.get("password"):
                s.login(mail["user"], mail["password"])
            s.send_message(msg)
        return True
    except Exception as e:
        print(f"watchdog: mail send failed: {e}")
        return False


def load_state():
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
            state.setdefault("problems", [])
            return state
    except Exception:
        return {"problems": [], "last_notified": 0}


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def check_problems(cfg) -> dict:
    """Return {problem_code: detail} for every problem currently active."""
    problems = {}

    if not service_active("dxspider.service"):
        problems["dxspider_down"] = "systemctl reports dxspider.service is NOT active."

    if not service_active("spiderweb.service"):
        problems["spiderweb_down"] = "systemctl reports spiderweb.service (web GUI) is NOT active."

    if "dxspider_down" not in problems:
        age = latest_spot_age_seconds(cfg)
        if age is None:
            problems["mysql_unreachable"] = (
                "dxspider.service is active, but the MySQL query for the "
                "latest spot failed (DB down or unreachable)."
            )
        elif age > FLOW_STALL_MINUTES * 60:
            problems["flow_stalled"] = (
                f"dxspider.service is active, but no new row has appeared in "
                f"dxcluster.spot for {age / 60:.0f} minutes "
                f"(threshold: {FLOW_STALL_MINUTES} minutes). Spiderweb is likely "
                f"showing stale/no data."
            )

    return problems


def main():
    cfg = load_config()
    now = time.time()

    problems = check_problems(cfg)

    state = load_state()
    prev = set(state.get("problems", []))
    current = set(problems)

    if current:
        should_notify = (
            current != prev
            or now - state.get("last_notified", 0) > REMINDER_MINUTES * 60
        )
        if should_notify:
            body = "\n\n".join(problems[code] for code in sorted(problems))
            send_mail(
                cfg,
                subject=f"[PA0ESH-3] ALERT: {', '.join(sorted(problems))}",
                body=f"{body}\n\nHost: dxcluster.pa0esh.nl\nTime: {time.ctime(now)}",
            )
            state["last_notified"] = now
    elif prev:
        send_mail(
            cfg,
            subject="[PA0ESH-3] RECOVERED",
            body=f"Previous problem(s) cleared: {', '.join(sorted(prev))}\n\nHost: dxcluster.pa0esh.nl\nTime: {time.ctime(now)}",
        )

    state["problems"] = sorted(current)
    save_state(state)


if __name__ == "__main__":
    main()

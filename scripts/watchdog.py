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

Auto-recovery: if a flow_stalled matches the known "mariadb.service was
restarted (e.g. by an unattended security upgrade) after dxspider's last
successful spot insert" signature, the DXSpider process is left holding a
stale MySQL handle. In that specific case only, this script attempts
`sudo systemctl restart dxspider.service` (requires the NOPASSWD sudoers
rule in /etc/sudoers.d/dxspider-watchdog) and always emails immediately
about the attempt and its outcome. It does NOT auto-restart for any other
cause of a stall, since dxspider being fine but simply receiving no spots
(e.g. an upstream network outage) would not be fixed by a restart and
would just needlessly disrupt connected users.
"""
import json
import os
import smtplib
import subprocess
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

BASE = Path("/home/sysop/spider/spiderweb")
CONFIG_FILE = BASE / "cfg" / "config.json"
STATE_FILE = BASE / "data" / "watchdog_state.json"

FLOW_STALL_MINUTES = 15
REMINDER_MINUTES = 60
AUTO_RESTART_COOLDOWN_MINUTES = 20
MAX_AUTO_RESTART_ATTEMPTS = 3


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


def mariadb_active_since_epoch() -> float | None:
    """Epoch time mariadb.service last entered the 'active' state, or None if unknown.
    Forces TZ=UTC on the subprocess so the timestamp always ends in a literal 'UTC'
    that Python can parse directly, avoiding a second shell-out to `date -d`."""
    try:
        r = subprocess.run(
            ["systemctl", "show", "mariadb.service", "--property=ActiveEnterTimestamp", "--value"],
            capture_output=True, text=True, timeout=10,
            env={**os.environ, "TZ": "UTC"},
        )
        ts = r.stdout.strip()
        if r.returncode != 0 or not ts or ts.lower() == "n/a":
            return None
        dt = datetime.strptime(ts, "%a %Y-%m-%d %H:%M:%S %Z").replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


def restart_dxspider() -> tuple[bool, str]:
    """Attempt `sudo systemctl restart dxspider.service` non-interactively."""
    try:
        r = subprocess.run(
            ["sudo", "-n", "systemctl", "restart", "dxspider.service"],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0:
            return True, "systemctl restart succeeded."
        return False, f"systemctl restart failed (exit {r.returncode}): {r.stderr.strip() or r.stdout.strip()}"
    except Exception as e:
        return False, f"exception while attempting restart: {e}"


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


def check_problems(cfg) -> tuple[dict, dict]:
    """Return ({problem_code: detail}, diagnostics) for every problem currently active."""
    problems = {}
    diagnostics = {}

    if not service_active("dxspider.service"):
        problems["dxspider_down"] = "systemctl reports dxspider.service is NOT active."

    if not service_active("spiderweb.service"):
        problems["spiderweb_down"] = "systemctl reports spiderweb.service (web GUI) is NOT active."

    if "dxspider_down" not in problems:
        age = latest_spot_age_seconds(cfg)
        diagnostics["spot_age_seconds"] = age
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

    return problems, diagnostics


def try_auto_recovery(cfg, problems: dict, diagnostics: dict, state: dict, now: float) -> str | None:
    """If flow_stalled matches the known mariadb-restart-stale-handle signature,
    attempt a bounded, cooldown-gated dxspider.service restart. Returns an email
    note describing the attempt, or None if no attempt was made."""
    if "flow_stalled" not in problems:
        state["auto_restart_attempts"] = 0
        return None

    attempts = state.get("auto_restart_attempts", 0)
    last_attempt = state.get("last_auto_restart", 0)
    if attempts >= MAX_AUTO_RESTART_ATTEMPTS:
        return None
    if now - last_attempt < AUTO_RESTART_COOLDOWN_MINUTES * 60:
        return None

    spot_age = diagnostics.get("spot_age_seconds")
    if spot_age is None:
        return None
    last_spot_epoch = now - spot_age
    mariadb_epoch = mariadb_active_since_epoch()
    if mariadb_epoch is None or mariadb_epoch <= last_spot_epoch:
        return None  # doesn't match the known signature; don't touch it

    ok, detail = restart_dxspider()
    state["auto_restart_attempts"] = attempts + 1
    state["last_auto_restart"] = now
    return (
        f"AUTO-RECOVERY ATTEMPTED (attempt {attempts + 1}/{MAX_AUTO_RESTART_ATTEMPTS}): "
        f"mariadb.service has been active since {time.ctime(mariadb_epoch)}, which is "
        f"after the last successful spot insert at {time.ctime(last_spot_epoch)} — this "
        f"matches the known 'DXSpider holding a stale MySQL handle after a mariadb "
        f"restart' signature. Ran `sudo systemctl restart dxspider.service`: "
        f"{'SUCCESS' if ok else 'FAILED'}. {detail}"
    )


def main():
    cfg = load_config()
    now = time.time()

    problems, diagnostics = check_problems(cfg)

    state = load_state()
    prev = set(state.get("problems", []))
    current = set(problems)

    auto_note = try_auto_recovery(cfg, problems, diagnostics, state, now)

    if current:
        should_notify = (
            current != prev
            or now - state.get("last_notified", 0) > REMINDER_MINUTES * 60
            or auto_note is not None
        )
        if should_notify:
            body = "\n\n".join(problems[code] for code in sorted(problems))
            if auto_note:
                body = f"{auto_note}\n\n{body}"
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

__author__ = "IU1BOW - Corrado"

import os
import json
import secrets
import threading
import logging
import logging.config
import asyncio
import datetime
import re
import smtplib
import socket
import telnetlib
from email.message import EmailMessage

import flask
from flask import request, render_template, send_file, abort, redirect, url_for, flash
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_minify import minify
import requests
import xmltodict

from lib.dxtelnet import fetch_who_and_version
from lib.adxo import get_adxo_events
from lib.qry import query_manager
from lib.cty import prefix_table
from lib.plot_data_provider import (
    ContinentsBandsProvider, SpotsPerMounthProvider, SpotsTrend, HourBand, WorldDxSpotsLive
)
from lib.qry_builder import query_build, query_build_callsign, query_build_callsing_list

# ----------------------------
# Timers
# ----------------------------
TIMER_VISIT = 1000
TIMER_ADXO  = 12 * 3600
TIMER_WHO   = 7 * 60

# ----------------------------
# Logging
# ----------------------------
logging.config.fileConfig("cfg/webapp_log_config.ini", disable_existing_loggers=True)
logger = logging.getLogger(__name__)
logger.info("Starting SPIDERWEB")

# ----------------------------
# Flask app & config
# ----------------------------
app = flask.Flask(__name__)

with open("cfg/config.json") as json_data_file:
    cfg = json.load(json_data_file)
logger.debug("CFG:")
logger.debug(cfg)

app.config["SECRET_KEY"] = cfg.get("secret_key") or secrets.token_hex(16)

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

csrf = CSRFProtect(app)
app.jinja_env.globals['csrf_token'] = lambda: generate_csrf()

with open("cfg/version.txt", "r") as version_file:
    app.config["VERSION"] = version_file.read().strip()
logger.info("Version:" + app.config["VERSION"])

if app.config.get("DEBUG"):
    minify(app=app, html=False, js=False, cssless=False)
else:
    minify(app=app, html=True, js=True, cssless=False)

app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

with open("cfg/bands.json") as json_bands:
    band_frequencies = json.load(json_bands)

with open("cfg/modes.json") as json_modes:
    modes_frequencies = json.load(json_modes)

with open("cfg/continents.json") as json_continents:
    continents_cq = json.load(json_continents)

# ----------------------------
# Mail-config
# ----------------------------
MAIL = cfg.get("mail_smtp", {}) or {}
MAIL_DEBUG = cfg.get("mail_debug", False)
MAIL_FORCE_IPV4 = bool(cfg.get("mail_force_ipv4", False))
MAIL_SIGNATURE = "\n73,\nErik, PA0ESH\n"

def _smtp_connect(host, port, timeout):
    if not MAIL_FORCE_IPV4:
        return smtplib.SMTP(host, port, timeout=timeout)
    infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        raise OSError("Could not resolve IPv4 address for SMTP host")
    af, socktype, proto, _, sa = infos[0]
    s = socket.socket(af, socktype, proto)
    s.settimeout(timeout)
    s.connect(sa)
    smtp = smtplib.SMTP()
    smtp.sock = s
    smtp.file = smtp.sock.makefile("rb")
    smtp._host = host
    code, msg = smtp.connect(host, port)
    return smtp

def send_mail(subject: str, body: str, to_addr: str) -> bool:
    if MAIL_DEBUG:
        logger.info("=== MAIL DEBUG MODE ===")
        logger.info(f"TO: {to_addr}")
        logger.info(f"SUBJECT: {subject}")
        logger.info("BODY:")
        for line in (body or "").splitlines():
            logger.info("    " + line)
        logger.info("=== END MAIL ===")
        return True

    if not MAIL:
        logger.error("Mail config missing; no mail sent.")
        return False

    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = MAIL.get("sender", MAIL.get("user"))
        msg["To"] = to_addr
        msg.set_content(body)

        with smtplib.SMTP(MAIL["host"], MAIL.get("port", 587), timeout=20) as s:
            if MAIL.get("use_tls", True):
                s.starttls()
            if MAIL.get("user") and MAIL.get("password"):
                s.login(MAIL["user"], MAIL["password"])
            s.send_message(msg)
        return True
    except Exception as e:
        logger.error(f"Mail send failed: {e}")
        return False

def _send_mail_async(subject: str, body: str, to_addr: str):
    threading.Thread(
        target=lambda: send_mail(subject, body, to_addr),
        daemon=True
    ).start()

# ----------------------------
# Visitors
# ----------------------------
visits_file_path = "data/visits.json"
try:
    with open(visits_file_path) as json_visitors:
        visits = json.load(json_visitors)
except (FileNotFoundError, json.decoder.JSONDecodeError):
    logger.warning("Visit json missing/invalid -> reset")
    visits = {}

def save_visits():
    os.makedirs(os.path.dirname(visits_file_path), exist_ok=True)
    with open(visits_file_path, "w") as json_file:
        json.dump(visits, json_file)
    logger.info("visit saved on: " + visits_file_path)

def schedule_save():
    save_visits()
    threading.Timer(TIMER_VISIT, schedule_save).start()
schedule_save()

enable_cq_filter = cfg.get("enable_cq_filter", "N")
if isinstance(enable_cq_filter, str):
    enable_cq_filter = enable_cq_filter.upper()
else:
    enable_cq_filter = "N"

pfxt = prefix_table()
qm   = query_manager()

def spotquery(parameters):
    try:
        if 'callsign' in parameters:
            logger.debug('search callsign')
            query_string = query_build_callsign(logger, parameters['callsign'])
        else:
            logger.debug('search with other filters')
            query_string = query_build(logger, parameters, band_frequencies, modes_frequencies, continents_cq, enable_cq_filter)

        qm.qry(query_string)
        data = qm.get_data()
        row_headers = qm.get_headers()

        if not data:
            logger.warning("no data found")

        payload = []
        for result in data or []:
            main_result = dict(zip(row_headers, result))
            search_prefix = pfxt.find(main_result["dx"])
            main_result["country"] = search_prefix["country"]
            main_result["iso"] = search_prefix["iso"]
            payload.append({**main_result})

        return payload
    except Exception as e:
        logger.error(e)
        return []

adxo_events = None
def get_adxo():
    global adxo_events
    adxo_events = get_adxo_events()
    threading.Timer(TIMER_ADXO, get_adxo).start()
get_adxo()

heatmap_cbp  = ContinentsBandsProvider(logger, qm, continents_cq, band_frequencies)
bar_graph_spm= SpotsPerMounthProvider(logger, qm)
line_graph_st= SpotsTrend(logger, qm)
bubble_graph_hb = HourBand(logger, qm, band_frequencies)
geo_graph_wdsl  = WorldDxSpotsLive(logger, qm, pfxt)

WHO_CACHE = "data/who.json"
whoj = {
    "data": [],
    "version": "Unknown",
    "last_updated": "No data",
    "last_success": "Never",
    "status": "init",
    "last_error": ""
}

try:
    if os.path.isfile(WHO_CACHE):
        with open(WHO_CACHE, "r") as f:
            cached = json.load(f)
            whoj.update({
                "data": cached.get("data", []),
                "version": cached.get("version", "Unknown"),
                "last_updated": cached.get("last_updated", "No data"),
                "last_success": cached.get("last_success", "Never"),
                "status": "cached",
                "last_error": ""
            })
            logger.info(f"Loaded WHO cache: users={len(whoj['data'])} ver={whoj['version']} at={whoj['last_success']}")
except Exception as e:
    logger.warning(f"WHO cache read failed: {e}")

def who_is_connected():
    global whoj
    host = cfg["telnet"]["telnet_host"]
    port = cfg["telnet"]["telnet_port"]
    user = cfg["telnet"]["telnet_user"]
    password = cfg["telnet"]["telnet_password"]

    logger.info(f"Refreshing WHO list and DXSpider version from: {host}:{port}")
    try:
        result = asyncio.run(asyncio.wait_for(
            fetch_who_and_version(host, port, user, password), timeout=12
        ))
        parsed_data, dxspider_version = result or ([], "Unknown")

        u = (user or "").upper()
        safe_data = [e for e in (parsed_data or []) if (e.get("callsign","").upper() != u)]

        nowz = datetime.datetime.now(datetime.timezone.utc).strftime("%d-%b-%Y %H:%MZ")

        whoj["data"] = safe_data
        whoj["version"] = dxspider_version or "Unknown"
        whoj["last_updated"] = nowz
        whoj["last_success"] = nowz
        whoj["status"] = "ok"
        whoj["last_error"] = ""

        try:
            os.makedirs(os.path.dirname(WHO_CACHE), exist_ok=True)
            with open(WHO_CACHE, "w") as f:
                json.dump({
                    "data": safe_data,
                    "version": whoj["version"],
                    "last_updated": nowz,
                    "last_success": nowz
                }, f)
        except Exception as ce:
            logger.warning(f"WHO cache write failed: {ce}")

        logger.debug(f"WHO ok: users={len(safe_data)} ver={whoj['version']} at={nowz}")

    except Exception as e:
        logger.error(f"WHO fetch error: {e}")
        whoj["status"] = "error"
        whoj["last_error"] = str(e)[:200]

    finally:
        threading.Timer(TIMER_WHO, who_is_connected).start()

who_is_connected()

inline_script_nonce = ""

def get_nonce():
    global inline_script_nonce
    inline_script_nonce = secrets.token_hex()
    return inline_script_nonce

def visitor_count():
    user_ip = request.environ.get('HTTP_X_FORWARDED_FOR') or request.environ.get('HTTP_X_REAL_IP') or request.remote_addr
    visits[user_ip] = visits.get(user_ip, 0) + 1

# ----------------------------
# Registratie - OPGESCHOOND
# ----------------------------
REG_FILE = "data/registrations.json"
os.makedirs(os.path.dirname(REG_FILE), exist_ok=True)

CALLSIGN_RE   = re.compile(r"^[A-Za-z0-9/]{3,20}$")
EMAIL_RE      = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LOCATOR_RE    = re.compile(r"^[A-Ra-r]{2}\d{2}([A-Xa-x]{2}(\d{2})?)?$")

def _load_regs():
    try:
        with open(REG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

def _save_regs(regs):
    with open(REG_FILE, "w") as f:
        json.dump(regs, f, indent=2)

def _clean(s):
    return (s or "").strip()

def _validate_registration(d):
    err = []
    cs = _clean(d.get("callsign")).upper()
    fn = _clean(d.get("firstname"))
    qth = _clean(d.get("qth"))
    loc = _clean(d.get("locator")).upper()
    em = _clean(d.get("email")).lower()

    if not CALLSIGN_RE.match(cs):
        err.append("Invalid callsign")
    if not fn:
        err.append("First name is required")
    if not qth:
        err.append("QTH is required")
    if not LOCATOR_RE.match(loc):
        err.append("Invalid QTH locator (must be 4/6/8 characters)")
    if not EMAIL_RE.match(em):
        err.append("Invalid e-mail address")

    return err, {"callsign": cs, "firstname": fn, "qth": qth, "locator": loc, "email": em}

def _find_reg(regs, reg_id):
    for r in regs:
        if r.get("id") == reg_id:
            return r
    return None

def _find_reg_by_callsign(regs, callsign_upper):
    for r in regs:
        if (r.get("callsign","").upper() == callsign_upper):
            return r
    return None

# ----------------------------
# ROUTES
# ----------------------------
@app.route("/spotlist", methods=["POST"])
@csrf.exempt
def spotlist():
    response = flask.Response(json.dumps(spotquery(request.json)))
    return response

@app.route("/", methods=["GET"])
@app.route("/index.html", methods=["GET"])
def spots():
    visitor_count()
    response = flask.Response(
        render_template(
            "index.html",
            inline_script_nonce=get_nonce(),
            mycallsign=cfg["mycallsign"],
            telnet=f"{cfg['telnet']['telnet_host']}:{cfg['telnet']['telnet_port']}",
            mail=cfg["mail"],
            menu_list=cfg["menu"]["menu_list"],
            visits=len(visits),
            enable_cq_filter=enable_cq_filter,
            timer_interval=cfg["timer"]["interval"],
            adxo_events=adxo_events,
            continents=continents_cq,
            bands=band_frequencies,
            dx_calls=get_dx_calls(),
        )
    )
    return response

def get_dx_calls():
    try:
        query_string = query_build_callsing_list()
        qm.qry(query_string)
        data = qm.get_data()
        row_headers = qm.get_headers()
        payload = []
        for result in data or []:
            main_result = dict(zip(row_headers, result))
            payload.append(main_result["dx"])
        logger.debug("last DX Callsigns:")
        logger.debug(payload)
        return payload
    except Exception:
        return []

@app.route("/service-worker.js", methods=["GET"])
def sw():
    return app.send_static_file("pwa/service-worker.js")

@app.route("/offline.html")
def root():
    return app.send_static_file("html/offline.html")

@app.route("/world.json")
def world_data():
    return app.send_static_file("data/world.json")

@app.route("/plots.html")
def plots():
    global whoj
    who_list = whoj.get("data") or []

    def _ctype(e):
        return (e.get("type") or e.get("Type") or "").upper()

    users_cnt = sum(1 for e in who_list if _ctype(e).startswith("USER"))
    nodes_cnt = sum(1 for e in who_list if _ctype(e).startswith("NODE"))
    rbn_cnt   = sum(1 for e in who_list if "RBN" in _ctype(e))

    response = flask.Response(
        render_template(
            "plots.html",
            inline_script_nonce=get_nonce(),
            mycallsign=cfg["mycallsign"],
            telnet=f"{cfg['telnet']['telnet_host']}:{cfg['telnet']['telnet_port']}",
            mail=cfg["mail"],
            menu_list=cfg["menu"]["menu_list"],
            visits=len(visits),
            who=who_list,
            last_updated=whoj.get("last_updated", "No data"),
            dxspider_version=whoj.get("version", "Unknown"),
            continents=continents_cq,
            bands=band_frequencies,
            users_cnt=users_cnt,
            nodes_cnt=nodes_cnt,
            rbn_cnt=rbn_cnt,
        )
    )
    return response

@app.route("/propagation.html")
def propagation():
    solar_data = {}
    url = "https://www.hamqsl.com/solarxml.php"
    try:
        logger.debug("connection to: " + url)
        req = requests.get(url, timeout=10)
        solar_data = xmltodict.parse(req.content)
    except Exception as e1:
        logger.error(e1)

    response = flask.Response(
        render_template(
            "propagation.html",
            inline_script_nonce=get_nonce(),
            mycallsign=cfg["mycallsign"],
            telnet=f"{cfg['telnet']['telnet_host']}:{cfg['telnet']['telnet_port']}",
            mail=cfg["mail"],
            menu_list=cfg["menu"]["menu_list"],
            visits=len(visits),
            solar_data=solar_data
        )
    )
    return response

@app.route("/cookies.html", methods=["GET"])
def cookies():
    response = flask.Response(
        render_template(
            "cookies.html",
            inline_script_nonce=get_nonce(),
            mycallsign=cfg["mycallsign"],
            telnet=f"{cfg['telnet']['telnet_host']}:{cfg['telnet']['telnet_port']}",
            mail=cfg["mail"],
            menu_list=cfg["menu"]["menu_list"],
            visits=len(visits),
        )
    )
    return response

@app.route("/privacy.html", methods=["GET"])
def privacy():
    response = flask.Response(
        render_template(
            "privacy.html",
            inline_script_nonce=get_nonce(),
            mycallsign=cfg["mycallsign"],
            telnet=f"{cfg['telnet']['telnet_host']}:{cfg['telnet']['telnet_port']}",
            mail=cfg["mail"],
            menu_list=cfg["menu"]["menu_list"],
            visits=len(visits),
        )
    )
    return response

@app.route("/sitemap.xml")
def sitemap():
    return app.send_static_file("sitemap.xml")

@app.route("/callsign.html", methods=["GET"])
def callsign():
    callsign = request.args.get("c")
    response = flask.Response(
        render_template(
            "callsign.html",
            inline_script_nonce=get_nonce(),
            mycallsign=cfg["mycallsign"],
            telnet=f"{cfg['telnet']['telnet_host']}:{cfg['telnet']['telnet_port']}",
            mail=cfg["mail"],
            menu_list=cfg["menu"]["menu_list"],
            visits=len(visits),
            timer_interval=cfg["timer"]["interval"],
            callsign=callsign,
            adxo_events=adxo_events,
            continents=continents_cq,
            bands=band_frequencies,
        )
    )
    return response

@app.route("/callsign", methods=["GET"])
def find_callsign():
    callsign = request.args.get("c")
    response = pfxt.find(callsign)
    if response is None:
        response = flask.Response(status=204)
    return response

@app.route("/plot_get_heatmap_data", methods=["POST"])
@csrf.exempt
def get_heatmap_data():
    continent = request.json.get('continent')
    response = flask.Response(json.dumps(heatmap_cbp.get_data(continent)))
    return response or flask.Response(status=204)

@app.route("/plot_get_dx_spots_per_month", methods=["POST"])
@csrf.exempt
def get_dx_spots_per_month():
    response = flask.Response(json.dumps(bar_graph_spm.get_data()))
    return response or flask.Response(status=204)

@app.route("/plot_get_dx_spots_trend", methods=["POST"])
@csrf.exempt
def get_dx_spots_trend():
    response = flask.Response(json.dumps(line_graph_st.get_data()))
    return response or flask.Response(status=204)

@app.route("/plot_get_hour_band", methods=["POST"])
@csrf.exempt
def get_dx_hour_band():
    response = flask.Response(json.dumps(bubble_graph_hb.get_data()))
    return response or flask.Response(status=204)

@app.route("/plot_get_world_dx_spots_live", methods=["POST"])
@csrf.exempt
def get_world_dx_spots_live():
    response = flask.Response(json.dumps(geo_graph_wdsl.get_data()))
    return response or flask.Response(status=204)

@app.get("/register")
def register_form():
    return render_template(
        "register.html",
        inline_script_nonce=get_nonce(),
        menu_list=cfg["menu"]["menu_list"],
        mycallsign=cfg.get("mycallsign",""),
        mail=cfg.get("mail",""),
        telnet=f"{cfg['telnet']['telnet_host']}:{cfg['telnet']['telnet_port']}",
        visits=len(visits),
    )

@app.post("/register")
def register_submit():
    form = request.form or {}
    errors, cleaned = _validate_registration(form)

    password = _clean(form.get("password"))
    password2 = _clean(form.get("password2"))
    
    if len(password) < 6:
        errors.append("Password moet minimaal 6 karakters zijn")
    if password != password2:
        errors.append("Passwords komen niet overeen")

    cs = cleaned["callsign"]

    regs = _load_regs()
    existing = _find_reg_by_callsign(regs, cs)

    if errors:
        for e in errors:
            flash(e, "danger")
        if existing:
            flash(f"Registratie voor {cs} bestaat al met status: {existing.get('status','unknown')}.", "info")
        return redirect(url_for("register_form"))

    if existing:
        return render_template(
            "register_thanks.html",
            inline_script_nonce=get_nonce(),
            menu_list=cfg["menu"]["menu_list"],
            mycallsign=cfg.get("mycallsign",""),
            mail=cfg.get("mail",""),
            telnet=f"{cfg['telnet']['telnet_host']}:{cfg['telnet']['telnet_port']}",
            visits=len(visits),
            callsign=cs,
            existing_status=existing.get("status","unknown")
        )

    reg_id = secrets.token_hex(8)
    entry = {
        "id": reg_id,
        "ts_utc": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "status": "pending",
        "password": password,
        **cleaned
    }
    regs.append(entry)
    _save_regs(regs)

    ack_ok = send_mail(
        subject="Registratie ontvangen – DXCluster",
        body=(
            f"Beste {cleaned['firstname']},\n\n"
            f"We hebben je registratie ontvangen:\n"
            f"  Callsign: {cleaned['callsign']}\n"
            f"  QTH: {cleaned['qth']}\n"
            f"  Locator: {cleaned['locator']}\n"
            f"  E-mail: {cleaned['email']}\n\n"
            "We controleren dit en laten je weten zodra je account is goedgekeurd."
            + MAIL_SIGNATURE
        ),
        to_addr=cleaned["email"]
    )
    if not ack_ok:
        logger.warning("Ontvangstbevestiging kon niet worden verzonden.")

    if MAIL.get("admin_notify"):
        _send_mail_async(
            subject=f"[DXCluster Registratie] {cleaned['callsign']}",
            body=(
                f"Nieuwe registratie aanvraag:\n\n"
                f"Callsign: {cleaned['callsign']}\n"
                f"Naam: {cleaned['firstname']}\n"
                f"QTH: {cleaned['qth']}\n"
                f"Locator: {cleaned['locator']}\n"
                f"E-mail: {cleaned['email']}\n"
                f"Password: {password}\n\n"
                f"HANDMATIG REGISTREREN:\n"
                f"1. Login op console.pl\n"
                f"2. set/register {cleaned['callsign']}\n"
                f"3. set/password {cleaned['callsign']} {password}\n"
                f"4. Daarna approve via: https://dxcluster.pa0esh.nl/admin/registrations\n"
                + MAIL_SIGNATURE
            ),
            to_addr=MAIL["admin_notify"]
        )

    return render_template(
        "register_thanks.html",
        inline_script_nonce=get_nonce(),
        menu_list=cfg["menu"]["menu_list"],
        mycallsign=cfg.get("mycallsign",""),
        mail=cfg.get("mail",""),
        telnet=f"{cfg['telnet']['telnet_host']}:{cfg['telnet']['telnet_port']}",
        visits=len(visits),
        callsign=cleaned["callsign"]
    )

@app.get("/admin/")
def admin_home():
    return render_template(
        "admin_index.html",
        inline_script_nonce=get_nonce(),
        menu_list=cfg["menu"]["menu_list"],
        mycallsign=cfg.get("mycallsign",""),
        mail=cfg.get("mail",""),
        telnet=f"{cfg['telnet']['telnet_host']}:{cfg['telnet']['telnet_port']}",
        visits=len(visits),
    )

@app.get("/admin/testmail")
def admin_testmail():
    to_addr = MAIL.get("admin_notify") or MAIL.get("sender") or MAIL.get("user")
    ok = send_mail(
        subject="DXCluster Spiderweb Testmail",
        body="This is a test mail from dxcluster.pa0esh.nl (Spiderweb)." + MAIL_SIGNATURE,
        to_addr=to_addr
    )
    flash(
        f"Test mail sent to {to_addr}" if ok else "Test mail failed.",
        "success" if ok else "danger"
    )
    return redirect(url_for("admin_home"))

@app.get("/admin/registrations")
def admin_regs():
    """Toon registraties - ZONDER trage DXSpider calls"""
    regs = _load_regs()
    regs.sort(key=lambda r: r.get("ts_utc",""), reverse=True)
    
    return render_template(
        "admin_registrations.html",
        inline_script_nonce=get_nonce(),
        regs=regs,
        visits=len(visits),
        menu_list=cfg["menu"]["menu_list"],
        mycallsign=cfg.get("mycallsign",""),
        mail=cfg.get("mail",""),
        telnet=f"{cfg['telnet']['telnet_host']}:{cfg['telnet']['telnet_port']}",
    )

@app.post("/admin/registrations/approve")
def admin_reg_approve():
    """Approve - stuurt alleen email, GEEN DXSpider calls"""
    reg_id = (request.form.get("id") or "").strip()
    regs = _load_regs()
    r = _find_reg(regs, reg_id)
    if not r:
        flash("Registratie niet gevonden", "danger")
        return redirect(url_for("admin_regs"))

    # Update status
    r["status"] = "approved"
    r["approved_at"] = datetime.datetime.utcnow().isoformat()
    _save_regs(regs)

    # Email naar user
    _send_mail_async(
        subject="DXCluster account geactiveerd",
        body=(
            f"Beste {r['firstname']},\n\n"
            f"Je account is nu actief!\n\n"
            f"Login gegevens:\n"
            f"Callsign: {r['callsign']}\n"
            f"Password: {r.get('password', '(not set)')}\n\n"
            f"Telnet: {cfg['telnet']['telnet_host']}:{cfg['telnet']['telnet_port']}\n"
            f"Web: https://dxcluster.pa0esh.nl\n"
            + MAIL_SIGNATURE
        ),
        to_addr=r["email"]
    )
    
    logger.info(f"Approved registration for {r['callsign']} - email sent")
    flash(f"{r['callsign']} goedgekeurd - email verzonden naar user", "success")
    return redirect(url_for("admin_regs"))

@app.post("/admin/registrations/reject")
def admin_reg_reject():
    reg_id = (request.form.get("id") or "").strip()
    regs = _load_regs()
    r = _find_reg(regs, reg_id)
    if not r:
        flash("Registration not found", "danger")
        return redirect(url_for("admin_regs"))
    r["status"] = "rejected"
    _save_regs(regs)

    _send_mail_async(
        subject="DXCluster registration rejected",
        body=(
            f"Dear {r['firstname']},\n\n"
            "Unfortunately your registration has been rejected. "
            "Feel free to contact info@pa0esh.com for details."
            + MAIL_SIGNATURE
        ),
        to_addr=r["email"]
    )
    flash("Rejected and e-mail queued.", "success")
    return redirect(url_for("admin_regs"))

@app.post("/admin/registrations/delete")
def admin_reg_delete():
    reg_id = (request.form.get("id") or "").strip()
    regs = _load_regs()
    r = _find_reg(regs, reg_id)
    if not r:
        flash("Registratie niet gevonden", "danger")
        return redirect(url_for("admin_regs"))
    
    regs = [x for x in regs if x.get("id") != reg_id]
    _save_regs(regs)
    
    flash(f"Registratie {r['callsign']} verwijderd", "success")
    return redirect(url_for("admin_regs"))

@app.route("/csp-reports", methods=['POST'])
@csrf.exempt
def csp_reports():
    report_data = request.get_data(as_text=True)
    logger.warning("CSP Report:")
    logger.warning(report_data)
    return flask.Response(status=204)

@app.after_request
def add_security_headers(resp):
    resp.headers["Strict-Transport-Security"] = "max-age=1000"
    resp.headers["X-Xss-Protection"] = "1; mode=block"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Cache-Control"] = "public, no-cache, must-revalidate, max-age=900"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["ETag"] = app.config["VERSION"]

    resp.headers["Content-Security-Policy"] = (
        "default-src 'self';"
        f"script-src 'self' cdnjs.cloudflare.com cdn.jsdelivr.net 'nonce-{inline_script_nonce}';"
        "style-src 'self' cdnjs.cloudflare.com cdn.jsdelivr.net 'unsafe-inline';"
        "object-src 'none';base-uri 'self';"
        "form-action 'self';"
        "connect-src 'self' cdn.jsdelivr.net cdnjs.cloudflare.com sidc.be prop.kc2g.com www.hamqsl.com;"
        "font-src 'self' cdn.jsdelivr.net;"
        "frame-src 'self';"
        "frame-ancestors 'none';"
        "img-src 'self' data: cdnjs.cloudflare.com sidc.be prop.kc2g.com www.hamqsl.com;"
        "manifest-src 'self';"
        "media-src 'self';"
        "worker-src 'self';"
        "report-uri /csp-reports;"
    )
    return resp

BACKUP_DIR = "/home/sysop/spider/backupSpiderweb"

def _safe_path(name: str) -> str:
    if not name or "/" in name or "\\" in name:
        abort(400, "invalid name")
    full = os.path.join(BACKUP_DIR, name)
    if not os.path.isfile(full):
        abort(404)
    return full

@app.route("/backup", methods=["GET"])
def backup_redirect():
    return redirect(url_for("backup_page"), code=301)

@app.route("/backup.html", methods=["GET"])
def backup_page():
    backups = []
    latest = None

    if os.path.isdir(BACKUP_DIR):
        for name in os.listdir(BACKUP_DIR):
            path = os.path.join(BACKUP_DIR, name)
            if not os.path.isfile(path) or name.endswith(".sh"):
                continue
            try:
                st = os.stat(path)
                mtime = datetime.datetime.utcfromtimestamp(st.st_mtime)
                size_kb = round(st.st_size / 1024)
                item = {
                    "name": name,
                    "size_bytes": st.st_size,
                    "size_kb": size_kb,
                    "mtime": mtime,
                    "mtime_str": mtime.strftime("%d-%m-%Y %H:%M"),
                }
                backups.append(item)
                if latest is None or mtime > latest["mtime"]:
                    latest = item
            except OSError:
                continue
        backups.sort(key=lambda x: x["mtime"], reverse=True)

    tel = cfg["telnet"]
    telnet_host = tel.get("telnet_host") or tel.get("host")
    telnet_port = tel.get("telnet_port") or tel.get("port")

    return render_template(
        "backup.html",
        inline_script_nonce=get_nonce(),
        menu_list=cfg["menu"]["menu_list"],
        backups=backups,
        latest_backup=latest,
        backup_dir=BACKUP_DIR,
        mycallsign=cfg.get("mycallsign", ""),
        mail=cfg.get("mail", ""),
        telnet=f"{telnet_host}:{telnet_port}",
        visits=len(visits),
    )

@app.get("/backup/download")
def backup_download():
    name = request.args.get("name", "")
    full = _safe_path(name)
    return send_file(full, as_attachment=True, download_name=name)

@app.post("/backup/restore_db")
def backup_restore_db():
    name = request.form.get("name", "")
    full = _safe_path(name)
    if not name.endswith(".sql") and not name.endswith(".sql.gz"):
        abort(400, "not a .sql file")
    host = cfg.get("db_host") or cfg["mysql"]["host"]
    db   = cfg.get("db_name") or cfg["mysql"]["db"]
    user = cfg.get("db_user") or cfg["mysql"]["user"]
    pw   = cfg.get("db_pass") or cfg["mysql"]["passwd"]
    
    if name.endswith(".sql.gz"):
        rc = os.system(f'gunzip < "{full}" | mysql -h {host} -u {user} -p{pw} {db}')
    else:
        rc = os.system(f'mysql -h {host} -u {user} -p{pw} {db} < "{full}"')
    
    flash(
        "DB restore completed. Now restart: sudo systemctl restart spiderweb" if rc == 0
        else f"DB restore failed (rc={rc})",
        "success" if rc == 0 else "danger"
    )
    return redirect(url_for("backup_page"))

@app.post("/backup/restore_app")
def backup_restore_app():
    name = request.form.get("name", "")
    full = _safe_path(name)
    if not name.endswith(".tar.gz"):
        abort(400, "not a .tar.gz file")
    import tempfile, shutil, subprocess
    tmp = tempfile.mkdtemp(prefix="sw-restore-")
    try:
        if subprocess.call(["tar", "-xzf", full, "-C", tmp]) != 0:
            flash("Extract failed", "danger")
            return redirect(url_for("backup_page"))
        rc = subprocess.call([
            "rsync","-a","--delete",
            "--exclude",".venv","--exclude","backupSpiderweb",
            f"{tmp}/", os.path.dirname(__file__) + "/"
        ])
        flash(
            "App restored. Now restart: sudo systemctl restart spiderweb" if rc == 0
            else f"Copy failed (rc={rc})",
            "success" if rc == 0 else "danger"
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return redirect(url_for("backup_page"))

@app.post("/backup/delete")
def backup_delete():
    name = request.form.get("name", "")
    full = _safe_path(name)
    try:
        os.remove(full)
        flash(f"Deleted: {name}", "success")
    except OSError as e:
        flash(f"Delete failed for {name}: {e}", "danger")
    return redirect(url_for("backup_page"))

@app.post("/backup/run")
def backup_run():
    import subprocess, datetime as dt

    script = "/home/sysop/spider/backupSpiderweb/backup_spiderweb.sh"
    ts = dt.datetime.utcnow().strftime("%Y%m%d-%H%M%SZ")
    log_path = os.path.join(BACKUP_DIR, f"backup_run-{ts}.log")

    try:
        proc = subprocess.run(
            ["/usr/bin/bash", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60*15,
            check=False,
            env=dict(os.environ, PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        )

        with open(log_path, "w") as f:
            f.write(proc.stdout or "")
        if proc.returncode == 0:
            flash(f"Backup started/completed. Log: {os.path.basename(log_path)}", "success")
        else:
            flash(f"Backup returned rc={proc.returncode}. See log: {os.path.basename(log_path)}", "danger")
    except FileNotFoundError:
        flash("backup_spiderweb.sh not found (check path).", "danger")
    except subprocess.TimeoutExpired:
        flash("Backup exceeded time limit (timeout). See log for partial output.", "danger")
    except Exception as e:
        flash(f"Backup error: {e}", "danger")

    return redirect(url_for("backup_page"))

if __name__ == "__main__":
    who_is_connected()
    app.run(host="0.0.0.0")
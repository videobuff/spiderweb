__author__ = "IU1BOW - Corrado"

import os
import json
import secrets
import threading
import logging
import logging.config
import asyncio
import datetime

import flask
from flask import request, render_template, send_file, abort, redirect, url_for, flash
from flask_wtf.csrf import CSRFProtect
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

# Timers
TIMER_VISIT = 1000
TIMER_ADXO  = 12 * 3600
TIMER_WHO   = 7 * 60

# Logging
logging.config.fileConfig("cfg/webapp_log_config.ini", disable_existing_loggers=True)
logger = logging.getLogger(__name__)
logger.info("Starting SPIDERWEB")

# Flask app
app = flask.Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(16)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=False,
    SESSION_COOKIE_SAMESITE="Strict",
)

# Version
with open("cfg/version.txt", "r") as version_file:
    app.config["VERSION"] = version_file.read().strip()
logger.info("Version:" + app.config["VERSION"])

inline_script_nonce = ""
csrf = CSRFProtect(app)

# Minify
if app.config.get("DEBUG"):
    minify(app=app, html=False, js=False, cssless=False)
else:
    minify(app=app, html=True, js=True, cssless=False)

# Jinja whitespace
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

# Configs
with open("cfg/config.json") as json_data_file:
    cfg = json.load(json_data_file)
logger.debug("CFG:")
logger.debug(cfg)

with open("cfg/bands.json") as json_bands:
    band_frequencies = json.load(json_bands)

with open("cfg/modes.json") as json_modes:
    modes_frequencies = json.load(json_modes)

with open("cfg/continents.json") as json_continents:
    continents_cq = json.load(json_continents)

# Visitors
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

# CQ filter
enable_cq_filter = cfg.get("enable_cq_filter", "N")
if isinstance(enable_cq_filter, str):
    enable_cq_filter = enable_cq_filter.upper()
else:
    enable_cq_filter = "N"

# Lookups/managers
pfxt = prefix_table()
qm   = query_manager()

# Spot query
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

# ADXO events (scheduled)
adxo_events = None
def get_adxo():
    global adxo_events
    adxo_events = get_adxo_events()
    threading.Timer(TIMER_ADXO, get_adxo).start()
get_adxo()

# Chart providers
heatmap_cbp  = ContinentsBandsProvider(logger, qm, continents_cq, band_frequencies)
bar_graph_spm= SpotsPerMounthProvider(logger, qm)
line_graph_st= SpotsTrend(logger, qm)
bubble_graph_hb = HourBand(logger, qm, band_frequencies)
geo_graph_wdsl  = WorldDxSpotsLive(logger, qm, pfxt)

# WHO / DXSpider version (robust + cache)
WHO_CACHE = "data/who.json"
whoj = {
    "data": [],
    "version": "Unknown",
    "last_updated": "No data",
    "last_success": "Never",
    "status": "init",
    "last_error": ""
}

# load cache on startup if exists
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

        # filter out the telnet user (case-insensitive)
        u = (user or "").upper()
        safe_data = [e for e in (parsed_data or []) if (e.get("callsign","").upper() != u)]

        nowz = datetime.datetime.now(datetime.timezone.utc).strftime("%d-%b-%Y %H:%MZ")

        whoj["data"] = safe_data
        whoj["version"] = dxspider_version or "Unknown"
        whoj["last_updated"] = nowz
        whoj["last_success"] = nowz
        whoj["status"] = "ok"
        whoj["last_error"] = ""

        # write cache
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
        # keep previous good info
        whoj["status"] = "error"
        whoj["last_error"] = str(e)[:200]

    finally:
        threading.Timer(TIMER_WHO, who_is_connected).start()

# Kick off
who_is_connected()

# Nonce generator for inline script blocks
def get_nonce():
    global inline_script_nonce
    inline_script_nonce = secrets.token_hex()
    return inline_script_nonce

# Visitors
def visitor_count():
    user_ip = request.environ.get('HTTP_X_FORWARDED_FOR') or request.environ.get('HTTP_X_REAL_IP') or request.remote_addr
    visits[user_ip] = visits.get(user_ip, 0) + 1

# ROUTES
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

# Plot data APIs
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

# CSP reports
@app.route("/csp-reports", methods=['POST'])
@csrf.exempt
def csp_reports():
    report_data = request.get_data(as_text=True)
    logger.warning("CSP Report:")
    logger.warning(report_data)
    return flask.Response(status=204)

# Security headers / CSP
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

# ===== Spiderweb Backup & Restore =====
BACKUP_DIR = "/home/sysop/spider/backupSpiderweb"

def _safe_path(name: str) -> str:
    if not name or "/" in name or "\\" in name:
        abort(400, "ongeldige naam")
    full = os.path.join(BACKUP_DIR, name)
    if not os.path.isfile(full):
        abort(404)
    return full

@app.route("/backup.html", methods=["GET"])
def backup_page():
    backups = []
    latest = None

    if os.path.isdir(BACKUP_DIR):
        for name in os.listdir(BACKUP_DIR):
            path = os.path.join(BACKUP_DIR, name)
            if not os.path.isfile(path):
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
    if not name.endswith(".sql"):
        abort(400, "geen .sql bestand")
    host = cfg.get("db_host") or cfg["mysql"]["host"]
    db   = cfg.get("db_name") or cfg["mysql"]["db"]
    user = cfg.get("db_user") or cfg["mysql"]["user"]
    pw   = cfg.get("db_pass") or cfg["mysql"]["passwd"]
    rc = os.system(f'mysql -h {host} -u {user} -p{pw} {db} < "{full}"')
    flash(
        "DB restore voltooid. Herstart nu: sudo systemctl restart spiderweb" if rc == 0
        else f"DB restore faalde (rc={rc})",
        "success" if rc == 0 else "danger"
    )
    return redirect(url_for("backup_page"))

@app.post("/backup/restore_app")
def backup_restore_app():
    name = request.form.get("name", "")
    full = _safe_path(name)
    if not name.endswith(".tar.gz"):
        abort(400, "geen .tar.gz bestand")
    import tempfile, shutil, subprocess
    tmp = tempfile.mkdtemp(prefix="sw-restore-")
    try:
        if subprocess.call(["tar", "-xzf", full, "-C", tmp]) != 0:
            flash("Uitpakken faalde", "danger")
            return redirect(url_for("backup_page"))
        rc = subprocess.call([
            "rsync","-a","--delete",
            "--exclude",".venv","--exclude","backupSpiderweb",
            f"{tmp}/", os.path.dirname(__file__) + "/"
        ])
        flash(
            "App hersteld. Herstart nu: sudo systemctl restart spiderweb" if rc == 0
            else f"Bestanden kopiëren faalde (rc={rc})",
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
        flash(f"Verwijderd: {name}", "success")
    except OSError as e:
        flash(f"Verwijderen mislukt voor {name}: {e}", "danger")
    return redirect(url_for("backup_page"))
@app.post("/backup/run")
def backup_run():
    import subprocess, datetime, tempfile, shlex

    script = "/home/sysop/spider/backupSpiderweb/backup_spiderweb.sh"
    ts = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%SZ")
    log_path = os.path.join(BACKUP_DIR, f"backup_run-{ts}.log")

    try:
        # voer script uit en vang stdout/stderr
        proc = subprocess.run(
            ["/usr/bin/bash", "/home/sysop/spider/backupSpiderweb/backup_spiderweb.sh"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60*15,
            check=False,
            env=dict(os.environ, PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        )

        # bewaar log in backup-dir
        with open(log_path, "w") as f:
            f.write(proc.stdout or "")
        if proc.returncode == 0:
            flash(f"Backup gestart/voltooid. Log: {os.path.basename(log_path)}", "success")
        else:
            flash(f"Backup gaf rc={proc.returncode}. Zie log: {os.path.basename(log_path)}", "danger")
    except FileNotFoundError:
        flash("backup_spiderweb.sh niet gevonden (pad controleren).", "danger")
    except subprocess.TimeoutExpired:
        flash("Backup overschreed de tijdslimiet (timeout). Zie log voor gedeeltelijke output.", "danger")
    except Exception as e:
        flash(f"Backup-fout: {e}", "danger")

    return redirect(url_for("backup_page"))

# ---- main ----
if __name__ == "__main__":
    who_is_connected()
    app.run(host="0.0.0.0")

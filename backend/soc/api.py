from __future__ import annotations

import os
import json
import subprocess
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from .db import db, fetch_one, fetch_all, execute

router = APIRouter(prefix="/soc", tags=["soc"])
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

SOC_ADMIN_TOKEN = os.getenv("SOC_ADMIN_TOKEN", "").strip()

def _require_admin(request: Request):
    token = request.headers.get("X-SOC-Token", "").strip()
    if not SOC_ADMIN_TOKEN or token != SOC_ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="forbidden")


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/api/metrics/latest")
def metrics_latest():
    with db() as conn:
        row = fetch_one(conn, "SELECT * FROM vw_soc_metrics_latest LIMIT 1")
        return row or {}


@router.get("/api/incidents/open")
def incidents_open(limit: int = 200):
    limit = max(1, min(int(limit), 1000))
    with db() as conn:
        rows = fetch_all(conn, "SELECT * FROM vw_soc_open_incidents LIMIT %s", (limit,))
        return rows


@router.get("/api/incidents/last24h")
def incidents_last24h():
    since = datetime.now() - timedelta(hours=24)
    with db() as conn:
        rows = fetch_all(conn, """
            SELECT id, grade, disruption_class, severity_score, title, message, first_seen, last_seen, reasons, metrics, response_actions
            FROM soc_incidents
            WHERE last_seen >= %s
            ORDER BY severity_score DESC, last_seen DESC
            LIMIT 2000
        """, (since,))
        return rows


@router.get("/api/incidents/grouped")
def incidents_grouped(hours: int = 24):
    """
    IP + payload_type(or inferred from incident_key)로 묶어서 보여주기.
    """
    hours = max(1, min(int(hours), 168))
    since = datetime.now() - timedelta(hours=hours)
    with db() as conn:
        rows = fetch_all(conn, """
            SELECT
              SUBSTRING_INDEX(SUBSTRING_INDEX(incident_key, ':', 2), ':', -1) AS ip,
              SUBSTRING_INDEX(incident_key, ':', -1) AS kind,
              MAX(severity_score) AS max_score,
              MAX(grade) AS max_grade,
              COUNT(*) AS cnt,
              MAX(last_seen) AS last_seen
            FROM soc_incidents
            WHERE last_seen >= %s
            GROUP BY ip, kind
            ORDER BY max_score DESC, last_seen DESC
            LIMIT 500
        """, (since,))
        return rows


@router.get("/api/logs/tail")
def logs_tail(kind: str = "nginx_access", lines: int = 100):
    """
    UI에서 '최근 로그 n줄' 보기용.
    kind: nginx_access/nginx_error/auth/ufw/fail2ban/app_auth/app_access/app_model
    """
    lines = max(10, min(int(lines), 1000))
    paths = {
        "nginx_access": os.getenv("SOC_NGINX_ACCESS_LOG", "/var/log/nginx/access.log"),
        "nginx_error":  os.getenv("SOC_NGINX_ERROR_LOG",  "/var/log/nginx/error.log"),
        "auth":         os.getenv("SOC_AUTH_LOG",         "/var/log/auth.log"),
        "ufw":          os.getenv("SOC_UFW_LOG",          "/var/log/ufw.log"),
        "fail2ban":     os.getenv("SOC_FAIL2BAN_LOG",     "/var/log/fail2ban.log"),
        "app_auth":     os.getenv("SOC_APP_AUTH_LOG",     "/home/prizux/prizux/backend/SoC/auth.log"),
        "app_access":   os.getenv("SOC_APP_ACCESS_LOG",   "/home/prizux/prizux/backend/SoC/access.log"),
        "app_model":    os.getenv("SOC_APP_MODEL_LOG",    "/home/prizux/prizux/backend/SoC/model.log"),
    }
    path = paths.get(kind)
    if not path:
        return {"path": None, "lines": []}

    try:
        out = subprocess.check_output(["tail", "-n", str(lines), path], text=True, stderr=subprocess.DEVNULL)
        arr = [ln for ln in out.splitlines() if ln.strip()]
    except Exception:
        arr = []
    return {"path": path, "lines": arr[-lines:]}


# =========================
# SOAR actions (token protected)
# =========================
@router.post("/api/actions/block-ip")
def action_block_ip(request: Request, ip: str, reason: str = "soc"):
    _require_admin(request)
    ip = (ip or "").strip()
    if not ip:
        raise HTTPException(400, "ip required")

    # 예: ufw deny (환경마다 다르니 최소)
    cmd = f"ufw deny from {ip} to any"
    ok = True
    err = None
    try:
        subprocess.check_output(["sudo", "ufw", "deny", "from", ip, "to", "any"], text=True, stderr=subprocess.STDOUT)
    except Exception as e:
        ok = False
        err = repr(e)

    with db() as conn:
        execute(conn, """
          INSERT INTO soc_actions (incident_id, action_type, target, requested_by, status, result_message, command_text)
          VALUES (NULL, 'block_ip', %s, 'operator', %s, %s, %s)
        """, (ip, "SUCCESS" if ok else "FAILED", (err or "ok"), cmd))

    return {"ok": ok, "ip": ip, "error": err}


@router.post("/api/actions/reload-nginx")
def action_reload_nginx(request: Request):
    _require_admin(request)

    cmd = "nginx -t && systemctl reload nginx"
    ok = True
    err = None
    try:
        subprocess.check_output(["sudo", "nginx", "-t"], text=True, stderr=subprocess.STDOUT)
        subprocess.check_output(["sudo", "systemctl", "reload", "nginx"], text=True, stderr=subprocess.STDOUT)
    except Exception as e:
        ok = False
        err = repr(e)

    with db() as conn:
        execute(conn, """
          INSERT INTO soc_actions (incident_id, action_type, target, requested_by, status, result_message, command_text)
          VALUES (NULL, 'reload_nginx', 'nginx', 'operator', %s, %s, %s)
        """, ("SUCCESS" if ok else "FAILED", (err or "ok"), cmd))

    return {"ok": ok, "error": err}


@router.get("/health")
def health():
    return {"ok": True}

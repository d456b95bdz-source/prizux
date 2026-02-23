from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Dict, List, Optional

# -----------------------------
# Tail state
# -----------------------------
class FileTailState:
    def __init__(self):
        self.offsets: Dict[str, int] = {}

    def read_new_lines(self, path: str, max_bytes: int = 2_000_000) -> List[str]:
        if not path or not os.path.exists(path):
            return []
        try:
            size = os.path.getsize(path)
        except Exception:
            return []

        last = self.offsets.get(path, 0)
        if size < last:
            last = 0  # rotated/truncated

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(last)
            data = f.read(max_bytes)
            self.offsets[path] = f.tell()

        return [ln for ln in data.splitlines() if ln.strip()]


# -----------------------------
# Regex: nginx access (default format)
# -----------------------------
# ex: 1.2.3.4 - - [16/Feb/2026:19:53:42 +0900] "GET / HTTP/1.1" 200 6571 "-" "UA"
NGINX_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<dt>[^\]]+)\]\s+"(?P<meth>[A-Z]+)\s+(?P<path>\S+)\s+[^"]+"\s+(?P<status>\d{3})\s+(?P<bytes>\d+)\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
)

def _parse_nginx_dt(s: str) -> datetime:
    # "16/Feb/2026:19:53:42 +0900"
    try:
        return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except Exception:
        return datetime.now()


# -----------------------------
# nginx error: upstream timed out / connect refused 등
# -----------------------------
NGINX_ERR_TIME_RE = re.compile(r"^(?P<dt>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})")
NGINX_UPSTREAM_TIMEOUT_RE = re.compile(r"upstream timed out.*client:\s*(?P<ip>[^,]+),.*request:\s*\"(?P<req>[^\"]+)\"")
NGINX_CONNECT_FAIL_RE = re.compile(r"connect\(\)\s+failed.*client:\s*(?P<ip>[^,]+),.*request:\s*\"(?P<req>[^\"]+)\"")


# -----------------------------
# /var/log/auth.log (sshd)
# -----------------------------
AUTH_FAIL_RE = re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>\S+)")
AUTH_OK_RE = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)")


# -----------------------------
# UFW kernel log
# -----------------------------
UFW_BLOCK_RE = re.compile(r"\[UFW BLOCK\].*SRC=(?P<src>\S+).*DPT=(?P<dpt>\d+)")


# -----------------------------
# Fail2ban
# -----------------------------
F2B_BAN_RE = re.compile(r"\bBan\s+(?P<ip>\S+)")
F2B_UNBAN_RE = re.compile(r"\bUnban\s+(?P<ip>\S+)")
F2B_FOUND_RE = re.compile(r"\bFound\s+(?P<ip>\S+)")


# -----------------------------
# App SoC logs (main.py RotatingFileHandler)
# ex: "2026-02-16 19:54:08 | ERROR | event=server_error path=/... err=..."
# -----------------------------
APP_LOG_RE = re.compile(r"^(?P<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\|\s+(?P<level>[A-Z]+)\s+\|\s+(?P<body>.*)$")
KV_RE = re.compile(r"(\w+)=([^\s]+)")


# -----------------------------
# Payload classification tokens
# -----------------------------
SSTI_TOKENS = ["{{", "{%", "__globals__", "cycler", "lipsum", "self", "request.application", "config"]
RCE_TOKENS = ["os.popen", "subprocess", "pty.spawn", "nc ", "bash", "curl ", "wget ", "python3 -c", "/bin/bash", "base64 -d"]
SQLI_TOKENS = [" union ", "select ", "sleep(", "benchmark(", "information_schema", "or 1=1", "'--", "\"--"]
TRAV_TOKENS = ["../", "%2e%2e", "/etc/passwd", ".env", "config.php"]

def _payload_type(text: str) -> Optional[str]:
    if not text:
        return None
    t = text.lower()

    if any(tok.lower() in t for tok in RCE_TOKENS):
        return "RCE"
    if any(tok.lower() in t for tok in SSTI_TOKENS):
        return "SSTI"
    if any(tok.lower() in t for tok in SQLI_TOKENS):
        return "SQLI"
    if any(tok.lower() in t for tok in TRAV_TOKENS):
        return "TRAVERSAL"

    return None


def parse_line(source: str, line: str) -> Optional[dict]:
    """
    Returns normalized event dict for soc_events insert.
    """
    src = (source or "").strip()

    if src == "nginx_access":
        m = NGINX_ACCESS_RE.search(line)
        if not m:
            return None
        dt = _parse_nginx_dt(m.group("dt"))
        ip = m.group("ip")
        method = m.group("meth")
        path = m.group("path")
        status = int(m.group("status"))
        bytes_out = int(m.group("bytes"))
        ua = m.group("ua") or ""
        return {
            "event_time": dt,
            "source": "nginx_access",
            "ip": ip,
            "method": method,
            "path": path,
            "status_code": status,
            "bytes_out": bytes_out,
            "bytes_in": None,
            "req_time_ms": None,
            "user_agent": ua[:1024],
            "account": None,
            "payload_type": _payload_type(path),
            "message": line[:4000],
        }

    if src == "nginx_error":
        # date at start "2026/02/16 18:29:35 ..."
        dt = datetime.now()
        mdt = NGINX_ERR_TIME_RE.search(line)
        if mdt:
            try:
                dt = datetime.strptime(mdt.group("dt"), "%Y/%m/%d %H:%M:%S")
            except Exception:
                dt = datetime.now()

        ip = None
        req = None
        ptype = None

        m = NGINX_UPSTREAM_TIMEOUT_RE.search(line)
        if m:
            ip = m.group("ip").strip()
            req = m.group("req").strip()
            ptype = "SLOWLORIS"  # upstream header timeout은 L7 저속/슬로우 계열의 강한 신호
        else:
            m2 = NGINX_CONNECT_FAIL_RE.search(line)
            if m2:
                ip = m2.group("ip").strip()
                req = m2.group("req").strip()
                ptype = "UPSTREAM_CONNECT_FAIL"

        if req and not ptype:
            ptype = _payload_type(req)

        return {
            "event_time": dt,
            "source": "nginx_error",
            "ip": ip,
            "method": None,
            "path": req,
            "status_code": 504 if ("timed out" in line) else None,
            "bytes_in": None,
            "bytes_out": None,
            "req_time_ms": None,
            "user_agent": None,
            "account": None,
            "payload_type": ptype,
            "message": line[:4000],
        }

    if src == "auth":
        # /var/log/auth.log - lines often ISO8601 in journald export, but also plain
        dt = datetime.now()
        # attempt parse first 19 chars like "2026-02-16T20:14:37"
        try:
            dt = datetime.strptime(line[:19], "%Y-%m-%dT%H:%M:%S")
        except Exception:
            pass

        mf = AUTH_FAIL_RE.search(line)
        if mf:
            user = mf.group("user")
            ip = mf.group("ip")
            return {
                "event_time": dt,
                "source": "auth",
                "ip": ip,
                "method": None,
                "path": f"ssh_login:{user}",
                "status_code": 401,
                "bytes_in": None,
                "bytes_out": None,
                "req_time_ms": None,
                "user_agent": None,
                "account": user,
                "payload_type": "BRUTE_ROOT" if user == "root" else "BRUTE",
                "message": line[:4000],
            }

        ms = AUTH_OK_RE.search(line)
        if ms:
            user = ms.group("user")
            ip = ms.group("ip")
            return {
                "event_time": dt,
                "source": "auth",
                "ip": ip,
                "method": None,
                "path": f"ssh_login_success:{user}",
                "status_code": 200,
                "bytes_in": None,
                "bytes_out": None,
                "req_time_ms": None,
                "user_agent": None,
                "account": user,
                "payload_type": "LOGIN_SUCCESS",
                "message": line[:4000],
            }

        return None

    if src == "ufw":
        dt = datetime.now()
        try:
            dt = datetime.strptime(line[:19], "%Y-%m-%dT%H:%M:%S")
        except Exception:
            pass

        m = UFW_BLOCK_RE.search(line)
        if not m:
            return None

        ip = m.group("src")
        dpt = m.group("dpt")
        return {
            "event_time": dt,
            "source": "ufw",
            "ip": ip,
            "method": None,
            "path": f"blocked_dpt:{dpt}",
            "status_code": 403,
            "bytes_in": None,
            "bytes_out": None,
            "req_time_ms": None,
            "user_agent": None,
            "account": None,
            "payload_type": "BLOCKED",
            "message": line[:4000],
        }

    if src == "fail2ban":
        dt = datetime.now()
        # fail2ban lines: "2026-02-16 19:22:21,715 fail2ban.actions [807]: NOTICE [sshd] Ban 1.2.3.4"
        try:
            dt = datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
        except Exception:
            pass

        mb = F2B_BAN_RE.search(line)
        if mb:
            ip = mb.group("ip")
            return {
                "event_time": dt,
                "source": "fail2ban",
                "ip": ip,
                "method": None,
                "path": "f2b_ban",
                "status_code": 403,
                "bytes_in": None,
                "bytes_out": None,
                "req_time_ms": None,
                "user_agent": None,
                "account": None,
                "payload_type": "NEUTRALIZED",
                "message": line[:4000],
            }

        mu = F2B_UNBAN_RE.search(line)
        if mu:
            ip = mu.group("ip")
            return {
                "event_time": dt,
                "source": "fail2ban",
                "ip": ip,
                "method": None,
                "path": "f2b_unban",
                "status_code": 200,
                "bytes_in": None,
                "bytes_out": None,
                "req_time_ms": None,
                "user_agent": None,
                "account": None,
                "payload_type": "UNBAN",
                "message": line[:4000],
            }

        mf = F2B_FOUND_RE.search(line)
        if mf:
            ip = mf.group("ip")
            return {
                "event_time": dt,
                "source": "fail2ban",
                "ip": ip,
                "method": None,
                "path": "f2b_found",
                "status_code": 401,
                "bytes_in": None,
                "bytes_out": None,
                "req_time_ms": None,
                "user_agent": None,
                "account": None,
                "payload_type": "BRUTE",
                "message": line[:4000],
            }
        return None

    if src in ("app_access", "app_auth", "app_model"):
        m = APP_LOG_RE.match(line)
        if not m:
            return None
        try:
            dt = datetime.strptime(m.group("dt"), "%Y-%m-%d %H:%M:%S")
        except Exception:
            dt = datetime.now()

        body = m.group("body") or ""
        kv = dict(KV_RE.findall(body))
        path = kv.get("path", None)
        ptype = _payload_type(path or body)

        return {
            "event_time": dt,
            "source": src,
            "ip": kv.get("ip", None),
            "method": kv.get("method", None),
            "path": path,
            "status_code": None,
            "bytes_in": None,
            "bytes_out": None,
            "req_time_ms": None,
            "user_agent": kv.get("ua", None),
            "account": kv.get("email", None) or kv.get("username", None),
            "payload_type": kv.get("payload", None) or ptype,
            "message": line[:4000],
        }

    return None

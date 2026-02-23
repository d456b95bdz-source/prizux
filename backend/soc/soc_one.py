from __future__ import annotations

import os
import time
import json
import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from .db import db, execute, executemany, fetch_one, fetch_all
from .parser import FileTailState, parse_line


# =========================
# ENV: log paths (너가 확정한 경로)
# =========================
LOG_NGINX_ACCESS = os.getenv("SOC_NGINX_ACCESS_LOG", "/var/log/nginx/access.log")
LOG_NGINX_ERROR  = os.getenv("SOC_NGINX_ERROR_LOG",  "/var/log/nginx/error.log")
LOG_AUTH         = os.getenv("SOC_AUTH_LOG",         "/var/log/auth.log")
LOG_UFW          = os.getenv("SOC_UFW_LOG",          "/var/log/ufw.log")
LOG_FAIL2BAN     = os.getenv("SOC_FAIL2BAN_LOG",     "/var/log/fail2ban.log")

LOG_APP_AUTH     = os.getenv("SOC_APP_AUTH_LOG",     "/home/prizux/prizux/backend/SoC/auth.log")
LOG_APP_ACCESS   = os.getenv("SOC_APP_ACCESS_LOG",   "/home/prizux/prizux/backend/SoC/access.log")
LOG_APP_MODEL    = os.getenv("SOC_APP_MODEL_LOG",    "/home/prizux/prizux/backend/SoC/model.log")

LOOKBACK_MINUTES = int(os.getenv("SOC_LOOKBACK_MINUTES", "10"))
INGEST_INTERVAL  = float(os.getenv("SOC_INGEST_INTERVAL_SEC", "1"))

# SOAR actions token (api에서 사용)
SOC_ADMIN_TOKEN = os.getenv("SOC_ADMIN_TOKEN", "").strip()

# =========================
# Severity (Containment)
# =========================
SEV_ORDER = ["SAFE", "EUCLID", "KETER", "APOLLYON"]
def sev_max(a: str, b: str) -> str:
    try:
        return a if SEV_ORDER.index(a) >= SEV_ORDER.index(b) else b
    except Exception:
        return a

# =========================
# Simple metrics windows
# =========================
WIN_60 = 60
WIN_24H = 24 * 3600

@dataclass
class MetricSnapshot:
    bucket_time: datetime
    req_per_sec_total: float
    ip_cardinality_1m: int
    bytes_out_per_sec: float
    path_uniqueness_rate: float
    p404_path_entropy: float
    ssti_token_hit_rate: float
    rce_token_hit_rate: float
    u_upstream_timeout_rate: float
    error_rate_total: float
    latency_p99_ms: float
    ip_recurrence_24h: float
    ais: float
    sis: float
    rsi: float


def now_ts() -> float:
    return time.time()

def floor_minute(dt: datetime) -> datetime:
    return dt.replace(second=0, microsecond=0)

def shannon_entropy(values) -> float:
    if not values:
        return 0.0
    text = "|".join(values)
    freq = Counter(text)
    total = len(text)
    ent = 0.0
    for c in freq.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent

def percentile(sorted_vals, q: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = int(q * (len(sorted_vals) - 1))
    return float(sorted_vals[max(0, min(idx, len(sorted_vals) - 1))])

def bucket_time_from_now() -> datetime:
    return floor_minute(datetime.now())

# =========================
# DB inserts
# =========================
EVENT_INSERT_SQL = """
INSERT INTO soc_events
(event_time, source, ip, method, path, status_code, bytes_in, bytes_out, req_time_ms, user_agent, account, payload_type, message)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
"""

METRIC_UPSERT_SQL = """
INSERT INTO soc_metrics_1m
(bucket_time,
 req_per_sec_total, bytes_out_per_sec, ip_cardinality_1m,
 path_uniqueness_rate, p404_path_entropy,
 ssti_token_hit_rate, rce_token_hit_rate, u_upstream_timeout_rate,
 error_rate_total, latency_p99_ms, ip_recurrence_24h,
 ais, sis, rsi,
 created_at)
VALUES (%s,
        %s,%s,%s,
        %s,%s,
        %s,%s,%s,
        %s,%s,%s,
        %s,%s,%s,
        NOW())
ON DUPLICATE KEY UPDATE
 req_per_sec_total=VALUES(req_per_sec_total),
 bytes_out_per_sec=VALUES(bytes_out_per_sec),
 ip_cardinality_1m=VALUES(ip_cardinality_1m),
 path_uniqueness_rate=VALUES(path_uniqueness_rate),
 p404_path_entropy=VALUES(p404_path_entropy),
 ssti_token_hit_rate=VALUES(ssti_token_hit_rate),
 rce_token_hit_rate=VALUES(rce_token_hit_rate),
 u_upstream_timeout_rate=VALUES(u_upstream_timeout_rate),
 error_rate_total=VALUES(error_rate_total),
 latency_p99_ms=VALUES(latency_p99_ms),
 ip_recurrence_24h=VALUES(ip_recurrence_24h),
 ais=VALUES(ais),
 sis=VALUES(sis),
 rsi=VALUES(rsi),
 updated_at=NOW()
"""

INCIDENT_UPSERT_SQL = """
INSERT INTO soc_incidents
(incident_key, is_open, grade, disruption_class, severity_score, title, message, source, first_seen, last_seen, tags, metrics, reasons, response_actions)
VALUES
(%s,1,%s,%s,%s,%s,%s,%s,NOW(),NOW(),%s,%s,%s,%s)
ON DUPLICATE KEY UPDATE
 is_open=1,
 grade=VALUES(grade),
 disruption_class=VALUES(disruption_class),
 severity_score=GREATEST(severity_score, VALUES(severity_score)),
 title=VALUES(title),
 message=VALUES(message),
 source=VALUES(source),
 last_seen=NOW(),
 tags=VALUES(tags),
 metrics=VALUES(metrics),
 reasons=VALUES(reasons),
 updated_at=NOW()
"""

INCIDENT_CLOSE_SQL = """
UPDATE soc_incidents
SET is_open=0, closed_at=NOW(), updated_at=NOW()
WHERE incident_key=%s AND is_open=1
"""

RULE_HIT_INSERT_SQL = """
INSERT INTO soc_rule_hits (event_id, incident_id, rule_name, rule_version, score, matched_value, created_at)
VALUES (%s,%s,%s,%s,%s,%s,NOW())
"""

# =========================
# Detector (in-memory window) + classify
# =========================
class Detector:
    def __init__(self):
        self.w60 = deque()     # (ts, event)
        self.w24h = deque()    # (ts, event)

    def ingest(self, ev: dict):
        t = now_ts()
        self.w60.append((t, ev))
        self.w24h.append((t, ev))

    def _trim(self):
        t = now_ts()
        cutoff60 = t - WIN_60
        while self.w60 and self.w60[0][0] < cutoff60:
            self.w60.popleft()

        cutoff24 = t - WIN_24H
        while self.w24h and self.w24h[0][0] < cutoff24:
            self.w24h.popleft()

    def compute_1m_metrics(self) -> Optional[MetricSnapshot]:
        self._trim()
        events_60 = [e for _, e in self.w60]
        if not events_60:
            return None

        total = len(events_60)
        rps = total / 60.0

        ips = [e.get("ip") for e in events_60 if e.get("ip")]
        ip_card = len(set(ips))

        bytes_out = sum(int(e.get("bytes_out") or 0) for e in events_60)
        bytes_out_per_sec = bytes_out / 60.0

        paths = [e.get("path") for e in events_60 if e.get("path")]
        uniq_paths = len(set(paths)) if paths else 0
        path_uniqueness = (uniq_paths / total) if total else 0.0
        path_entropy = shannon_entropy(list(set(paths))[:2000])

        # 5xx
        s5 = 0
        for e in events_60:
            sc = e.get("status_code")
            if sc is not None and int(sc) >= 500:
                s5 += 1
        error_rate_total = (s5 / total) if total else 0.0

        # latency p99 (req_time_ms)
        lat_ms = [int(e["req_time_ms"]) for e in events_60 if e.get("req_time_ms") is not None]
        lat_ms.sort()
        p99_ms = percentile(lat_ms, 0.99)

        # token hits per minute => rate per sec or per minute? 여기서는 "분당"을 60초로 나눈 rate(초당)로 저장
        ssti_hits = sum(1 for e in events_60 if e.get("payload_type") == "SSTI")
        rce_hits  = sum(1 for e in events_60 if e.get("payload_type") == "RCE")
        ssti_rate = ssti_hits / 60.0
        rce_rate  = rce_hits / 60.0

        # nginx_error upstream timeout rate
        upstream_timeout = sum(1 for e in events_60 if e.get("payload_type") == "SLOWLORIS")
        u_upstream_timeout_rate = upstream_timeout / 60.0

        # recurrence 24h
        events_24h = [e for _, e in self.w24h]
        severe_ips = [
            e.get("ip")
            for e in events_24h
            if e.get("ip") and e.get("payload_type") in ("RCE", "SSTI", "SQLI", "TRAVERSAL")
        ]
        ip_recur = 0
        if severe_ips:
            ip_recur = max(Counter(severe_ips).values(), default=0)

        # Derived indexes (AIS/SIS/RSI) - 0~100
        AIS = min(100.0, (rps * 2.0) + (ip_card * 1.5) + (ssti_hits * 5.0) + (rce_hits * 10.0) + (error_rate_total * 200.0))
        SIS = min(100.0, (error_rate_total * 300.0) + ((p99_ms / 1000.0) * 20.0) + (u_upstream_timeout_rate * 50.0))
        RSI = min(100.0, (path_uniqueness * 100.0) + (path_entropy * 10.0))

        return MetricSnapshot(
            bucket_time=bucket_time_from_now(),
            req_per_sec_total=round(rps, 4),
            ip_cardinality_1m=int(ip_card),
            bytes_out_per_sec=round(bytes_out_per_sec, 4),
            path_uniqueness_rate=round(path_uniqueness, 4),
            p404_path_entropy=round(path_entropy, 6),
            ssti_token_hit_rate=round(ssti_rate, 4),
            rce_token_hit_rate=round(rce_rate, 4),
            u_upstream_timeout_rate=round(u_upstream_timeout_rate, 4),
            error_rate_total=round(error_rate_total, 4),
            latency_p99_ms=round(p99_ms, 2),
            ip_recurrence_24h=float(ip_recur),
            ais=round(AIS, 4),
            sis=round(SIS, 4),
            rsi=round(RSI, 4),
        )

    def classify(self, snap: MetricSnapshot) -> Optional[dict]:
        """
        SAFE/EUCLID/KETER/APOLLYON
        """
        reasons = []
        sev = "SAFE"

        # KETER: RCE 1회라도 나오면 즉시
        if snap.rce_token_hit_rate > 0:
            sev = "KETER"
            reasons.append("RCE token detected")

        # EUCLID: SSTI burst / 정찰성 급증
        if snap.ssti_token_hit_rate >= (3 / 60.0):  # 분당 3 이상
            sev = sev_max(sev, "EUCLID")
            reasons.append("SSTI burst")

        if snap.path_uniqueness_rate >= 0.6:
            sev = sev_max(sev, "EUCLID")
            reasons.append("High path uniqueness")

        # APOLLYON: 서비스 영향(5xx/timeout/SIS/AIS) 중심
        if snap.error_rate_total >= 0.15:
            sev = sev_max(sev, "APOLLYON")
            reasons.append("5xx spike")

        if snap.u_upstream_timeout_rate >= (2 / 60.0):  # 분당 2 이상
            sev = sev_max(sev, "APOLLYON")
            reasons.append("Upstream timeout spike (possible slowloris/slot exhaustion)")

        if snap.ais >= 80:
            sev = sev_max(sev, "APOLLYON")
            reasons.append("High AIS")

        if snap.sis >= 70:
            sev = sev_max(sev, "APOLLYON")
            reasons.append("High SIS")

        if sev == "SAFE":
            return None

        # severity_score: 0~100
        sev_score = max(snap.ais, snap.sis, snap.rsi)

        return {
            "grade": sev,
            "severity_score": round(float(sev_score), 2),
            "reasons": reasons[:10],
            "metrics": {
                "req_per_sec_total": snap.req_per_sec_total,
                "ip_cardinality_1m": snap.ip_cardinality_1m,
                "bytes_out_per_sec": snap.bytes_out_per_sec,
                "path_uniqueness_rate": snap.path_uniqueness_rate,
                "p404_path_entropy": snap.p404_path_entropy,
                "ssti_token_hit_rate": snap.ssti_token_hit_rate,
                "rce_token_hit_rate": snap.rce_token_hit_rate,
                "u_upstream_timeout_rate": snap.u_upstream_timeout_rate,
                "error_rate_total": snap.error_rate_total,
                "latency_p99_ms": snap.latency_p99_ms,
                "ip_recurrence_24h": snap.ip_recurrence_24h,
                "ais": snap.ais,
                "sis": snap.sis,
                "rsi": snap.rsi,
            },
        }


# =========================
# Incident key: IP + payload_type(행위) 묶기
# =========================
def incident_key_from_events(events_60: list, grade: str) -> str:
    """
    KETER/EUCLID/APOLLYON이면:
      - 가장 많이 등장한 ip + 가장 강한 payload_type 기준으로 묶음
    """
    ips = [e.get("ip") for e in events_60 if e.get("ip")]
    ip = Counter(ips).most_common(1)[0][0] if ips else "unknown"

    # payload priority
    prio = {"RCE": 5, "SSTI": 4, "SQLI": 3, "TRAVERSAL": 2, "SLOWLORIS": 2, "BRUTE_ROOT": 2, "BRUTE": 1}
    types = [e.get("payload_type") for e in events_60 if e.get("payload_type")]
    if types:
        best = max(types, key=lambda t: prio.get(t, 0))
    else:
        best = "unknown"

    return f"{grade}:{ip}:{best}"


def _insert_events(conn, events: list) -> list:
    """
    Insert events and return inserted ids if needed.
    MySQL executemany doesn't return ids for each row reliably.
    여기서는 rule_hits 연결을 강제하지 않으니 id는 생략.
    """
    rows = []
    for e in events:
        rows.append((
            e["event_time"],
            e["source"],
            e.get("ip"),
            e.get("method"),
            e.get("path"),
            e.get("status_code"),
            e.get("bytes_in"),
            e.get("bytes_out"),
            e.get("req_time_ms"),
            e.get("user_agent"),
            e.get("account"),
            e.get("payload_type"),
            e.get("message"),
        ))
    if rows:
        executemany(conn, EVENT_INSERT_SQL, rows)
    return []


def _upsert_metric(conn, snap: MetricSnapshot):
    execute(conn, METRIC_UPSERT_SQL, (
        snap.bucket_time,
        snap.req_per_sec_total,
        snap.bytes_out_per_sec,
        snap.ip_cardinality_1m,
        snap.path_uniqueness_rate,
        snap.p404_path_entropy,
        snap.ssti_token_hit_rate,
        snap.rce_token_hit_rate,
        snap.u_upstream_timeout_rate,
        snap.error_rate_total,
        snap.latency_p99_ms,
        snap.ip_recurrence_24h,
        snap.ais,
        snap.sis,
        snap.rsi,
    ))


def _upsert_incident(conn, inc_key: str, grade: str, severity_score: float, title: str, message: str, source: str, metrics: dict, reasons: list, disruption: str = None):
    execute(conn, INCIDENT_UPSERT_SQL, (
        inc_key,
        grade,
        disruption,
        severity_score,
        title[:255],
        message[:4000] if message else None,
        source,
        json.dumps(["soc", "auto"], ensure_ascii=False),
        json.dumps(metrics, ensure_ascii=False),
        json.dumps(reasons, ensure_ascii=False),
        json.dumps([], ensure_ascii=False),
    ))


# =========================
# Main loop
# =========================
def main():
    state = FileTailState()
    det = Detector()

    log_sources = [
        ("nginx_access", LOG_NGINX_ACCESS),
        ("nginx_error",  LOG_NGINX_ERROR),
        ("auth",         LOG_AUTH),
        ("ufw",          LOG_UFW),
        ("fail2ban",     LOG_FAIL2BAN),
        ("app_auth",     LOG_APP_AUTH),
        ("app_access",   LOG_APP_ACCESS),
        ("app_model",    LOG_APP_MODEL),
    ]

    last_bucket = floor_minute(datetime.now())
    buf_events = []

    while True:
        # 1) ingest new lines
        for src, path in log_sources:
            for line in state.read_new_lines(path):
                ev = parse_line(src, line)
                if not ev:
                    continue

                # req_time_ms: nginx access 기본 포맷엔 없음 => None 유지
                # (나중에 nginx log_format을 json로 바꾸면 req_time_ms 채울 수 있음)
                det.ingest(ev)
                buf_events.append(ev)

        # 2) flush events to DB periodically (every loop)
        if buf_events:
            with db() as conn:
                _insert_events(conn, buf_events)
            buf_events.clear()

        # 3) each minute: compute metrics + incident
        now_dt = datetime.now()
        current_bucket = floor_minute(now_dt)
        if current_bucket != last_bucket:
            snap = det.compute_1m_metrics()
            if snap:
                with db() as conn:
                    _upsert_metric(conn, snap)

                alert = det.classify(snap)
                if alert:
                    # use last 60s events for grouping key
                    events_60 = [e for _, e in det.w60]
                    inc_key = incident_key_from_events(events_60, alert["grade"])

                    # title/message
                    title = f"[{alert['grade']}] SOC auto-detected"
                    msg = " / ".join(alert["reasons"][:5])

                    with db() as conn:
                        _upsert_incident(
                            conn,
                            inc_key=inc_key,
                            grade=alert["grade"],
                            severity_score=float(alert["severity_score"]),
                            title=title,
                            message=msg,
                            source="soc_one",
                            metrics=alert["metrics"],
                            reasons=alert["reasons"],
                            disruption=None,
                        )

            last_bucket = current_bucket

        time.sleep(INGEST_INTERVAL)


if __name__ == "__main__":
    main()

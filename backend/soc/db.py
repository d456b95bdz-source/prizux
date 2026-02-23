import os
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pymysql
from pymysql.cursors import DictCursor


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if not v:
        return default
    try:
        return int(v)
    except Exception:
        return default


def get_conn():
    """
    SOC 전용 DB(prizux_soc) 연결.
    .env:
      SOC_DB_HOST, SOC_DB_PORT, SOC_DB_USER, SOC_DB_PASSWORD, SOC_DB_NAME
    """
    return pymysql.connect(
        host=os.getenv("SOC_DB_HOST", "127.0.0.1"),
        port=_env_int("SOC_DB_PORT", 3306),
        user=os.getenv("SOC_DB_USER", "prizux_soc_user"),
        password=os.getenv("SOC_DB_PASSWORD", ""),
        database=os.getenv("SOC_DB_NAME", "prizux_soc"),
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=True,
    )


@contextmanager
def db():
    conn = get_conn()
    try:
        yield conn
    finally:
        conn.close()


def fetch_one(conn, sql: str, args: Optional[Tuple[Any, ...]] = None) -> Optional[Dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(sql, args or ())
        return cur.fetchone()


def fetch_all(conn, sql: str, args: Optional[Tuple[Any, ...]] = None) -> List[Dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(sql, args or ())
        return list(cur.fetchall())


def execute(conn, sql: str, args: Optional[Tuple[Any, ...]] = None) -> int:
    with conn.cursor() as cur:
        return cur.execute(sql, args or ())


def executemany(conn, sql: str, rows: Iterable[Tuple[Any, ...]]) -> int:
    with conn.cursor() as cur:
        return cur.executemany(sql, list(rows))

import os
import re
import hmac
import secrets
import hashlib
import logging
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import quote, quote_plus

import resend
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from sqlalchemy import (
    create_engine,
    String,
    BigInteger,
    DateTime,
    Integer,
    ForeignKey,
    UniqueConstraint,
    Index,
    select,
    and_,
    func,
    text,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from jinja2 import Environment, select_autoescape
from markupsafe import escape

# ✅ error202 앱 마운트를 위한 import
import error202

# =========================================================
# 1. ENV 및 설정 (먼저 로드)
# =========================================================
load_dotenv("/home/prizux/prizux/backend/.env")

APP_ENV = os.getenv("APP_ENV", "prod")
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://prizux.com").rstrip("/")

DB_HOST = os.getenv("DB_HOST", "127.0.0.1").strip()
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "prizux_user").strip()
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "prizux_db").strip()

RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
MAIL_FROM = os.getenv("MAIL_FROM", "Prizux Auth <auth@prizux.com>")

APP_SECRET = os.getenv("APP_SECRET", "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET")
OTP_SECRET = os.getenv("OTP_SECRET", "CHANGE_THIS_TO_ANOTHER_LONG_RANDOM_SECRET")

OTP_TTL_MINUTES = int(os.getenv("OTP_TTL_MINUTES", "10"))
IP_DAILY_LIMIT = int(os.getenv("IP_DAILY_LIMIT", "3"))
SIGNUP_IP_DAILY_LIMIT = int(os.getenv("SIGNUP_IP_DAILY_LIMIT", str(IP_DAILY_LIMIT)))
RECOVERY_IP_DAILY_LIMIT = int(os.getenv("RECOVERY_IP_DAILY_LIMIT", str(IP_DAILY_LIMIT)))

LOGIN_MAX_FAILS = int(os.getenv("LOGIN_MAX_FAILS", "10"))
LOGIN_WINDOW_MIN = int(os.getenv("LOGIN_WINDOW_MIN", "15"))
LOGIN_LOCK_MIN = int(os.getenv("LOGIN_LOCK_MIN", "15"))

# =========================================================
# 2. PATH / LOGGING
# =========================================================
BASE_DIR = Path("/home/prizux/prizux")
BACKEND_DIR = BASE_DIR / "backend"
FRONTEND_DIR = BASE_DIR / "frontend"
SOC_DIR = BACKEND_DIR / "SoC"
SOC_DIR.mkdir(parents=True, exist_ok=True)

AUTH_LOG_PATH = SOC_DIR / "auth.log"
ACCESS_LOG_PATH = SOC_DIR / "access.log"
MODEL_LOG_PATH = SOC_DIR / "model.log"

def _build_logger(name: str, path: Path) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = RotatingFileHandler(path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
        fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", "%Y-%m-%d %H:%M:%S")
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    logger.propagate = False
    return logger

auth_logger = _build_logger("auth_logger", AUTH_LOG_PATH)
access_logger = _build_logger("access_logger", ACCESS_LOG_PATH)
model_logger = _build_logger("model_logger", MODEL_LOG_PATH)

# =========================================================
# 3. DATABASE CONFIG
# =========================================================
def build_mysql_url(user, password, host, port, dbname, charset="utf8mb4"):
    user_enc = quote(user, safe="")
    pw_enc = quote_plus(password)
    return f"mysql+pymysql://{user_enc}:{pw_enc}@{host}:{port}/{dbname}?charset={charset}"

DATABASE_URL = build_mysql_url(DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=3600,
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY

# =========================================================
# 4. MODELS
# =========================================================
class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email", name="uq_users_email"),
        UniqueConstraint("username", name="uq_users_username"),
        Index("ix_users_email", "email"),
        Index("ix_users_username", "username"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    username: Mapped[str] = mapped_column(String(50), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    email_verified: Mapped[int] = mapped_column(Integer, default=0)
    email_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

class OtpCode(Base):
    __tablename__ = "otp_codes"
    __table_args__ = (
        Index("ix_otp_email_purpose_created", "email", "purpose", "created_at"),
        Index("ix_otp_ip_purpose_created", "ip_addr", "purpose", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255))
    purpose: Mapped[str] = mapped_column(String(20))
    otp_hash: Mapped[str] = mapped_column(String(128))
    ip_addr: Mapped[str] = mapped_column(String(64))
    consumed: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    __table_args__ = (
        Index("ix_reset_user_expires", "user_id", "expires_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"))
    token_hash: Mapped[str] = mapped_column(String(128), unique=True)
    consumed: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    __table_args__ = (
        Index("ix_login_attempt_ip_created", "ip_addr", "created_at"),
        Index("ix_login_attempt_email_created", "email", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ip_addr: Mapped[str] = mapped_column(String(64))
    email: Mapped[str] = mapped_column(String(255))
    success: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

# =========================================================
# 5. SCHEMAS
# =========================================================
class SignupSendCodeReq(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: EmailStr
    username: str = Field(min_length=4, max_length=30)
    password: str = Field(min_length=8, max_length=128)

class SignupVerifyReq(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: EmailStr
    username: str = Field(min_length=4, max_length=30)
    password: str = Field(min_length=8, max_length=128)
    code: str = Field(pattern=r"^\d{8}$")

class LoginReq(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: EmailStr
    username: str = Field(min_length=4, max_length=30)
    password: str = Field(min_length=8, max_length=128)

class RecoverySendCodeReq(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: EmailStr
    username: str = Field(min_length=4, max_length=30)

class RecoveryVerifyReq(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: EmailStr
    username: str = Field(min_length=4, max_length=30)
    code: str = Field(pattern=r"^\d{8}$")

class ResetPasswordReq(BaseModel):
    token: str = Field(min_length=32, max_length=256)
    new_password: str = Field(min_length=8, max_length=128)

# =========================================================
# 6. APP 초기화 및 LIFESPAN
# =========================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        Base.metadata.create_all(bind=engine)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            conn.commit()
        auth_logger.info("startup complete: Database connected")
    except Exception as e:
        auth_logger.exception(f"startup_db_error={repr(e)}")
    yield

app = FastAPI(title="Prizux Auth API", lifespan=lifespan)

# ✅ error202 앱 마운트
app.mount("/__err", error202.app)

# SSTI 방어용 Jinja2 (네 기존 코드 유지)
env = Environment(autoescape=select_autoescape(["html", "xml"]))

# =========================================================
# 7. ERROR PAGE BUILDER (main.py 내부 fallback)
# =========================================================
def build_error_html(invalid_path: str, status_code: int = 404) -> str:

    raw_path = invalid_path or "/"



    template_source = r"""

    <!DOCTYPE html>

    <html lang="ko">

    <head>

        <meta charset="UTF-8" /><title>SYSTEM CRITICAL ERROR</title>

        <style>

            @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');

            body { background: #000; color: #0f0; font-family: 'Share Tech Mono', monospace; display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 100vh; margin: 0; text-align: center; overflow: hidden; }

            .glitch { font-size: 5rem; font-weight: bold; color: #fff; text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff; animation: glitch 725ms infinite; margin: 0; }

            @keyframes glitch { 0% { text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff; } 50% { text-shadow: -0.05em -0.025em 0 #fc00ff, 0.025em 0.04em 0 #fffc00; } 100% { text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff; } }

            .path-info { background: #111; padding: 10px 20px; color: #2563eb; border: 1px solid #333; font-size: 1.2rem; margin-top: 10px; display: inline-block; }

            .rick { font-size: 10px; white-space: pre; color: rgba(0,255,0,0.3); margin-top: 30px; line-height: 1.1; font-family: monospace; }

            .status { color: #ff0033; font-weight: bold; letter-spacing: 2px; }

        </style>

    </head>

    <body>

        <div class="glitch">ERROR {{ status_code }}</div>

        <p class="status">CRITICAL PROTOCOL VIOLATION DETECTED</p>



        <p>FAILED_PATH: <span class="path-info">""" + raw_path + r"""</span></p>



        <div class="rick">

    _

   / )

  _ ( /

 / \ / /

( ) / /

 \/\/ /

  | |

        </div>

        <p style="font-size: 0.8rem; color: #444;">PRIZUX CORE OS v2.0.2-ERR_BYPASS</p>

    </body>

    </html>

    """

    return env.from_string(template_source).render(status_code=status_code)
# =========================================================
# 8. CORS & MIDDLEWARE
# =========================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://prizux.com",
        "https://www.prizux.com",
        "http://prizux.com",
        "http://www.prizux.com",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

def log_access(req: Request, status: int):
    xff = req.headers.get("x-forwarded-for", "").strip()
    ip = xff.split(",")[0].strip() if xff else (req.client.host if req.client else "0.0.0.0")
    access_logger.info(f'{ip} "{req.method} {req.url.path}" status={status}')

@app.middleware("http")
async def access_log_middleware(request: Request, call_next):
    try:
        response = await call_next(request)
        log_access(request, response.status_code)
        return response
    except Exception:
        log_access(request, 500)
        raise

# =========================================================
# 9. UTILS
# =========================================================
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{4,30}$")
PW_MIN_COMPLEX = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).{8,128}$")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def now_utc():
    return datetime.now(timezone.utc)

def normalize_email(email: str):
    return email.strip().lower()

def get_client_ip(request: Request):
    xff = request.headers.get("x-forwarded-for", "").strip()
    return xff.split(",")[0].strip() if xff else (request.client.host if request.client else "0.0.0.0")

def hmac_sha256(secret, text_value):
    return hmac.new(secret.encode("utf-8"), text_value.encode("utf-8"), hashlib.sha256).hexdigest()

def gen_otp_8():
    return "".join(secrets.choice("0123456789") for _ in range(8))

def hash_password(pw):
    return ph.hash(pw)

def verify_password(pw, pw_hash):
    try:
        return ph.verify(pw_hash, pw)
    except (VerifyMismatchError, InvalidHash):
        return False
    except Exception:
        return False

def validate_username(u):
    if not USERNAME_RE.fullmatch(u):
        raise HTTPException(400, "invalid username format")

def validate_password_strength(p):
    if not PW_MIN_COMPLEX.fullmatch(p):
        raise HTTPException(400, "password too weak")

def is_email_send_limited(db, ip, purpose, limit):
    day_start = now_utc().replace(hour=0, minute=0, second=0, microsecond=0)
    cnt = db.execute(
        select(func.count(OtpCode.id)).where(
            and_(OtpCode.ip_addr == ip, OtpCode.purpose == purpose, OtpCode.created_at >= day_start)
        )
    ).scalar_one()
    return cnt >= limit

def send_otp_email(to_email, otp, purpose):
    if not RESEND_API_KEY:
        raise HTTPException(500, "mail server error")
    title = "인증 코드" if purpose == "signup" else "계정 복구 코드"
    resend.Emails.send(
        {"from": MAIL_FROM, "to": [to_email], "subject": f"[Prizux] {title}", "html": f"코드: {otp}"}
    )

def log_auth(event, ip, email=None, username=None, extra=None):
    auth_logger.info(f"event={event} ip={ip} email={email or '-'} username={username or '-'} extra={extra or '-'}")

def login_locked(db, ip, email):
    window = now_utc() - timedelta(minutes=LOGIN_WINDOW_MIN)
    fails = db.execute(
        select(func.count(LoginAttempt.id)).where(
            and_(
                LoginAttempt.created_at >= window,
                LoginAttempt.success == 0,
                LoginAttempt.ip_addr == ip,
                LoginAttempt.email == email,
            )
        )
    ).scalar_one()
    return fails >= LOGIN_MAX_FAILS

# =========================================================
# 10. ROUTES
# =========================================================
@app.get("/", include_in_schema=False)
def serve_main():
    return FileResponse(FRONTEND_DIR / "main.html")

@app.get("/login", include_in_schema=False)
def serve_login():
    return FileResponse(FRONTEND_DIR / "login.html")

@app.get("/signup", include_in_schema=False)
def serve_signup():
    return FileResponse(FRONTEND_DIR / "signup.html")

@app.post("/api/v1/auth/signup/send-code")
def signup_send_code(payload: SignupSendCodeReq, request: Request, db: Session = Depends(get_db)):
    ip, email, username = get_client_ip(request), normalize_email(str(payload.email)), payload.username.strip()
    validate_username(username)
    validate_password_strength(payload.password)

    if db.execute(select(User.id).where(User.username == username)).scalar_one_or_none():
        raise HTTPException(409, "username exists")
    if db.execute(select(User.id).where(User.email == email)).scalar_one_or_none():
        raise HTTPException(409, "email exists")
    if is_email_send_limited(db, ip, "signup", SIGNUP_IP_DAILY_LIMIT):
        raise HTTPException(429, "too many requests")

    otp = gen_otp_8()
    db.add(
        OtpCode(
            email=email,
            purpose="signup",
            otp_hash=hmac_sha256(OTP_SECRET, f"{email}|signup|{otp}"),
            ip_addr=ip,
            expires_at=now_utc() + timedelta(minutes=OTP_TTL_MINUTES),
        )
    )
    db.commit()
    send_otp_email(email, otp, "signup")
    log_auth("signup_code_sent", ip, email, username)
    return {"ok": True}

@app.post("/api/v1/auth/signup/verify")
def signup_verify(payload: SignupVerifyReq, request: Request, db: Session = Depends(get_db)):
    ip, email, username = get_client_ip(request), normalize_email(str(payload.email)), payload.username.strip()
    validate_username(username)
    validate_password_strength(payload.password)

    otp_hash = hmac_sha256(OTP_SECRET, f"{email}|signup|{payload.code}")
    otp_row = db.execute(
        select(OtpCode).where(
            and_(
                OtpCode.email == email,
                OtpCode.purpose == "signup",
                OtpCode.consumed == 0,
                OtpCode.expires_at >= now_utc(),
                OtpCode.otp_hash == otp_hash,
            )
        )
    ).scalar_one_or_none()

    if not otp_row:
        raise HTTPException(400, "invalid code")

    otp_row.consumed = 1
    db.add(
        User(
            email=email,
            username=username,
            password_hash=hash_password(payload.password),
            email_verified=1,
            email_verified_at=now_utc(),
        )
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "duplicate account")

    log_auth("signup_success", ip, email, username)
    return {"ok": True}

@app.post("/api/v1/auth/login")
def login(payload: LoginReq, request: Request, db: Session = Depends(get_db)):
    ip, email, username = get_client_ip(request), normalize_email(str(payload.email)), payload.username.strip()

    if login_locked(db, ip, email):
        raise HTTPException(429, "locked")

    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    ok = verify_password(payload.password, user.password_hash) if user and user.username == username else False

    db.add(LoginAttempt(ip_addr=ip, email=email, success=1 if ok else 0))
    db.commit()

    if not ok:
        raise HTTPException(401, "failed")

    return {"ok": True}

@app.post("/api/v1/auth/recovery/send-code")
def recovery_send_code(payload: RecoverySendCodeReq, request: Request, db: Session = Depends(get_db)):
    ip, email, username = get_client_ip(request), normalize_email(str(payload.email)), payload.username.strip()

    if is_email_send_limited(db, ip, "recovery", RECOVERY_IP_DAILY_LIMIT):
        raise HTTPException(429, "too many requests")

    user = db.execute(select(User).where(and_(User.email == email, User.username == username))).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "not found")

    otp = gen_otp_8()
    db.add(
        OtpCode(
            email=email,
            purpose="recovery",
            otp_hash=hmac_sha256(OTP_SECRET, f"{email}|recovery|{otp}"),
            ip_addr=ip,
            expires_at=now_utc() + timedelta(minutes=OTP_TTL_MINUTES),
        )
    )
    db.commit()
    send_otp_email(email, otp, "recovery")
    return {"ok": True}

@app.post("/api/v1/auth/recovery/verify")
def recovery_verify(payload: RecoveryVerifyReq, request: Request, db: Session = Depends(get_db)):
    email = normalize_email(str(payload.email))

    otp_hash = hmac_sha256(OTP_SECRET, f"{email}|recovery|{payload.code}")
    otp_row = db.execute(
        select(OtpCode).where(
            and_(
                OtpCode.email == email,
                OtpCode.purpose == "recovery",
                OtpCode.consumed == 0,
                OtpCode.expires_at >= now_utc(),
                OtpCode.otp_hash == otp_hash,
            )
        )
    ).scalar_one_or_none()

    if not otp_row:
        raise HTTPException(400, "invalid code")

    otp_row.consumed = 1
    user = db.execute(select(User).where(User.email == email)).scalar_one()
    raw_token = secrets.token_urlsafe(48)
    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=hmac_sha256(APP_SECRET, raw_token),
            expires_at=now_utc() + timedelta(minutes=30),
        )
    )
    db.commit()
    return {"ok": True, "reset_token": raw_token}

@app.post("/api/v1/auth/recovery/reset-password")
def recovery_reset_password(payload: ResetPasswordReq, db: Session = Depends(get_db)):
    validate_password_strength(payload.new_password)

    t_hash = hmac_sha256(APP_SECRET, payload.token)
    token_row = db.execute(
        select(PasswordResetToken).where(
            and_(
                PasswordResetToken.token_hash == t_hash,
                PasswordResetToken.consumed == 0,
                PasswordResetToken.expires_at >= now_utc(),
            )
        )
    ).scalar_one_or_none()

    if not token_row:
        raise HTTPException(400, "invalid token")

    user = db.execute(select(User).where(User.id == token_row.user_id)).scalar_one()
    user.password_hash = hash_password(payload.new_password)
    token_row.consumed = 1
    db.commit()
    return {"ok": True}

@app.get("/health")
def health_check():
    return {"ok": True, "env": APP_ENV}

# =========================================================
# 11. ERROR HANDLERS
# =========================================================
@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    # API는 JSON
    if request.url.path.startswith("/api/v1"):
        return JSONResponse(status_code=404, content={"ok": False, "detail": "Not Found"})

    # 웹은 error202가 있으면 우선 사용
    try:
        return HTMLResponse(status_code=404, content=error202.build_error_html(request.url.path, 404))
    except Exception:
        # fallback
        return HTMLResponse(status_code=404, content=build_error_html(request.url.path, 404))

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/v1"):
        return JSONResponse(status_code=exc.status_code, content={"ok": False, "detail": exc.detail})
    return HTMLResponse(status_code=exc.status_code, content=build_error_html(request.url.path, exc.status_code))

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    auth_logger.exception(f"event=server_error path={request.url.path} err={repr(exc)}")
    if request.url.path.startswith("/api/v1"):
        return JSONResponse(status_code=500, content={"ok": False, "detail": "internal server error"})
    return HTMLResponse(status_code=500, content=build_error_html(request.url.path, 500))

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
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator
from sqlalchemy import (
    create_engine, String, BigInteger, DateTime, Integer, ForeignKey,
    UniqueConstraint, Index, select, and_, func, text,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from jinja2 import Environment
from soc.api import router as soc_router
load_dotenv("/home/prizux/prizux/backend/.env")
DB_USER = os.getenv("DB_USER", "prizux_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "prizux_db")
DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=3600, future=True, connect_args={"connect_timeout": 10, "program_name": "prizux_api"})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
APP_ENV = os.getenv("APP_ENV", "prod")
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://prizux.com").rstrip("/")
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
TRUSTED_PROXY_IPS = {ip.strip() for ip in os.getenv("TRUSTED_PROXY_IPS", "127.0.0.1").split(",") if ip.strip()}
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "https://prizux.com,https://www.prizux.com").split(",") if o.strip()]
ALLOW_CREDENTIALS = os.getenv("CORS_ALLOW_CREDENTIALS", "false").lower() == "true"

BASE_DIR = Path("/home/prizux/prizux")
BACKEND_DIR = BASE_DIR / "backend"
FRONTEND_DIR = BASE_DIR / "frontend"
SOC_LOG_DIR = BACKEND_DIR / "SoC"
SOC_LOG_DIR.mkdir(parents=True, exist_ok=True)
SOC_CODE_DIR = BACKEND_DIR / "soc"
AUTH_LOG_PATH = SOC_LOG_DIR / "auth.log"
ACCESS_LOG_PATH = SOC_LOG_DIR / "access.log"
MODEL_LOG_PATH = SOC_LOG_DIR / "model.log"

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

def _sanitize_log_value(v: Optional[str], max_len: int = 300) -> str:
    if v is None: return "-"
    s = str(v).replace("\n", "\\n").replace("\r", "\\r")
    return s[:max_len] + "...(truncated)" if len(s) > max_len else s

auth_logger = _build_logger("auth_logger", AUTH_LOG_PATH)
access_logger = _build_logger("access_logger", ACCESS_LOG_PATH)
model_logger = _build_logger("model_logger", MODEL_LOG_PATH)

ph = PasswordHasher()
jinja_env = Environment(autoescape=False)

class Base(DeclarativeBase): pass

class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email", name="uq_users_email"), UniqueConstraint("username", name="uq_users_username"), Index("ix_users_email", "email"), Index("ix_users_username", "username"))
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    username: Mapped[str] = mapped_column(String(50), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    email_verified: Mapped[int] = mapped_column(Integer, default=0)
    email_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class OtpCode(Base):
    __tablename__ = "otp_codes"
    __table_args__ = (Index("ix_otp_email_purpose_created", "email", "purpose", "created_at"), Index("ix_otp_ip_purpose_created", "ip_addr", "purpose", "created_at"))
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
    __table_args__ = (Index("ix_reset_user_expires", "user_id", "expires_at"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"))
    token_hash: Mapped[str] = mapped_column(String(128), unique=True)
    consumed: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    __table_args__ = (Index("ix_login_attempt_ip_created", "ip_addr", "created_at"), Index("ix_login_attempt_email_created", "email", "created_at"))
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ip_addr: Mapped[str] = mapped_column(String(64))
    email: Mapped[str] = mapped_column(String(255))
    success: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{4,30}$")
PW_MIN_COMPLEX = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).{8,128}$")

class SignupSendCodeReq(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: EmailStr
    username: str = Field(min_length=4, max_length=30)
    password: str = Field(min_length=8, max_length=128)
    @field_validator("username")
    @classmethod
    def _v_username(cls, v: str) -> str:
        if not USERNAME_RE.fullmatch(v): raise ValueError("invalid username format")
        return v

class SignupVerifyReq(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: EmailStr
    username: str = Field(min_length=4, max_length=30)
    password: str = Field(min_length=8, max_length=128)
    code: str = Field(pattern=r"^\d{8}$")
    @field_validator("username")
    @classmethod
    def _v_username(cls, v: str) -> str:
        if not USERNAME_RE.fullmatch(v): raise ValueError("invalid username format")
        return v

class LoginReq(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: EmailStr
    username: str = Field(min_length=4, max_length=30)
    password: str = Field(min_length=8, max_length=128)
    @field_validator("username")
    @classmethod
    def _v_username(cls, v: str) -> str:
        if not USERNAME_RE.fullmatch(v): raise ValueError("invalid username format")
        return v

class RecoverySendCodeReq(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: EmailStr
    username: str = Field(min_length=4, max_length=30)
    @field_validator("username")
    @classmethod
    def _v_username(cls, v: str) -> str:
        if not USERNAME_RE.fullmatch(v): raise ValueError("invalid username format")
        return v

class RecoveryVerifyReq(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: EmailStr
    username: str = Field(min_length=4, max_length=30)
    code: str = Field(pattern=r"^\d{8}$")
    @field_validator("username")
    @classmethod
    def _v_username(cls, v: str) -> str:
        if not USERNAME_RE.fullmatch(v): raise ValueError("invalid username format")
        return v

class ResetPasswordReq(BaseModel):
    token: str = Field(min_length=32, max_length=256)
    new_password: str = Field(min_length=8, max_length=128)

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        Base.metadata.create_all(bind=engine)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            conn.commit()
        auth_logger.info("startup complete: Database connected")
    except Exception as e:
        auth_logger.exception("startup_db_error=%s", _sanitize_log_value(repr(e), 800))
    yield

app = FastAPI(title="Prizux Auth API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_credentials=ALLOW_CREDENTIALS, allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["Content-Type", "Authorization", "X-Requested-With"], expose_headers=[], max_age=600)
app.include_router(soc_router)
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
    return response

async def build_error_html(path: str, code: int) -> str:
    template_str = f"""
    <html>
        <head><title>{code} Error</title></head>
        <body style="font-family: sans-serif; padding: 20px;">
            <h1>Error {code}</h1>
            <p>The path <b>{path}</b> was not found or caused an issue.</p>
            <hr>
            <i>Prizux Security Server</i>
        </body>
    </html>
    """
    t = jinja_env.from_string(template_str)
    return t.render()

@app.exception_handler(404)
async def custom_404_handler(request: Request, exc: Exception):
    if request.url.path.startswith("/api/v1"):
        return JSONResponse(status_code=404, content={"ok": False, "detail": "Not Found"})
    content = await build_error_html(request.url.path, 404)
    return HTMLResponse(content=content, status_code=404)

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    if request.url.path.startswith("/api/v1"):
        return JSONResponse(status_code=500, content={"ok": False, "detail": "Internal Server Error"})
    content = await build_error_html(request.url.path, 500)
    return HTMLResponse(content=content, status_code=500)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def now_utc(): return datetime.now(timezone.utc)
def normalize_email(email: str): return email.strip().lower()
def get_client_ip(request: Request):
    client_host = request.client.host if request.client else "0.0.0.0"
    xff = request.headers.get("x-forwarded-for", "").strip()
    if client_host in TRUSTED_PROXY_IPS and xff:
        first_ip = xff.split(",")[0].strip()
        if re.fullmatch(r"[0-9a-fA-F\.:]{3,45}", first_ip): return first_ip
    return client_host

def hmac_sha256(secret, text_value): return hmac.new(secret.encode("utf-8"), text_value.encode("utf-8"), hashlib.sha256).hexdigest()
def gen_otp_8(): return "".join(secrets.choice("0123456789") for _ in range(8))
def hash_password(pw): return ph.hash(pw)
def verify_password(pw, pw_hash):
    try: return ph.verify(pw_hash, pw)
    except: return False

def validate_password_strength(p):
    if not PW_MIN_COMPLEX.fullmatch(p): raise HTTPException(400, "password too weak")

def is_email_send_limited(db, ip, purpose, limit):
    day_start = now_utc().replace(hour=0, minute=0, second=0, microsecond=0)
    cnt = db.execute(select(func.count(OtpCode.id)).where(and_(OtpCode.ip_addr == ip, OtpCode.purpose == purpose, OtpCode.created_at >= day_start))).scalar_one()
    return cnt >= limit

def send_otp_email(to_email, otp, purpose):
    if not RESEND_API_KEY: raise HTTPException(500, "mail server error")
    title = "인증 코드" if purpose == "signup" else "계정 복구 코드"
    resend.Emails.send({"from": MAIL_FROM, "to": [to_email], "subject": f"[Prizux] {title}", "html": f"코드: {otp}"})

def log_auth(event, ip, email=None, username=None, extra=None):
    auth_logger.info("event=%s ip=%s email=%s username=%s extra=%s", _sanitize_log_value(event), _sanitize_log_value(ip), _sanitize_log_value(email), _sanitize_log_value(username), _sanitize_log_value(extra))

def login_locked(db, ip, email):
    window = now_utc() - timedelta(minutes=LOGIN_WINDOW_MIN)
    fails = db.execute(select(func.count(LoginAttempt.id)).where(and_(LoginAttempt.created_at >= window, LoginAttempt.success == 0, LoginAttempt.ip_addr == ip, LoginAttempt.email == email))).scalar_one()
    return fails >= LOGIN_MAX_FAILS

@app.get("/", include_in_schema=False)
def serve_main(): return FileResponse(FRONTEND_DIR / "main.html")
@app.get("/login", include_in_schema=False)
def serve_login(): return FileResponse(FRONTEND_DIR / "login.html")
@app.get("/signup", include_in_schema=False)
def serve_signup(): return FileResponse(FRONTEND_DIR / "signup.html")

@app.post("/api/v1/auth/signup/send-code")
def signup_send_code(payload: SignupSendCodeReq, request: Request, db: Session = Depends(get_db)):
    ip = get_client_ip(request)
    email = normalize_email(str(payload.email))
    username = payload.username.strip()
    validate_password_strength(payload.password)
    if db.execute(select(User.id).where(User.username == username)).scalar_one_or_none(): raise HTTPException(409, "username exists")
    if db.execute(select(User.id).where(User.email == email)).scalar_one_or_none(): raise HTTPException(409, "email exists")
    if is_email_send_limited(db, ip, "signup", SIGNUP_IP_DAILY_LIMIT): raise HTTPException(429, "too many requests")
    otp = gen_otp_8()
    db.add(OtpCode(email=email, purpose="signup", otp_hash=hmac_sha256(OTP_SECRET, f"{email}|signup|{otp}"), ip_addr=ip, expires_at=now_utc() + timedelta(minutes=OTP_TTL_MINUTES)))
    db.commit()
    send_otp_email(email, otp, "signup")
    log_auth("signup_code_sent", ip, email, username)
    return {"ok": True}

@app.post("/api/v1/auth/signup/verify")
def signup_verify(payload: SignupVerifyReq, request: Request, db: Session = Depends(get_db)):
    ip = get_client_ip(request)
    email = normalize_email(str(payload.email))
    username = payload.username.strip()
    validate_password_strength(payload.password)
    otp_hash = hmac_sha256(OTP_SECRET, f"{email}|signup|{payload.code}")
    otp_row = db.execute(select(OtpCode).where(and_(OtpCode.email == email, OtpCode.purpose == "signup", OtpCode.consumed == 0, OtpCode.expires_at >= now_utc(), OtpCode.otp_hash == otp_hash))).scalar_one_or_none()
    if not otp_row: raise HTTPException(400, "invalid code")
    otp_row.consumed = 1
    db.add(User(email=email, username=username, password_hash=hash_password(payload.password), email_verified=1, email_verified_at=now_utc()))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "duplicate account")
    log_auth("signup_success", ip, email, username)
    return {"ok": True}

@app.post("/api/v1/auth/login")
def login(payload: LoginReq, request: Request, db: Session = Depends(get_db)):
    ip = get_client_ip(request)
    email = normalize_email(str(payload.email))
    username = payload.username.strip()
    if login_locked(db, ip, email): raise HTTPException(429, "locked")
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    ok = verify_password(payload.password, user.password_hash) if user and user.username == username else False
    db.add(LoginAttempt(ip_addr=ip, email=email, success=1 if ok else 0))
    db.commit()
    if not ok: raise HTTPException(401, "failed")
    log_auth("login_success", ip, email, username)
    return {"ok": True}

@app.post("/api/v1/auth/forgot/send-code")
@app.post("/api/v1/auth/recovery/send-code")
def recovery_send_code(payload: RecoverySendCodeReq, request: Request, db: Session = Depends(get_db)):
    ip = get_client_ip(request)
    email = normalize_email(str(payload.email))
    username = payload.username.strip()
    if is_email_send_limited(db, ip, "recovery", RECOVERY_IP_DAILY_LIMIT): raise HTTPException(429, "too many requests")
    user = db.execute(select(User).where(and_(User.email == email, User.username == username))).scalar_one_or_none()
    if not user: raise HTTPException(404, "not found")
    otp = gen_otp_8()
    db.add(OtpCode(email=email, purpose="recovery", otp_hash=hmac_sha256(OTP_SECRET, f"{email}|recovery|{otp}"), ip_addr=ip, expires_at=now_utc() + timedelta(minutes=OTP_TTL_MINUTES)))
    db.commit()
    send_otp_email(email, otp, "recovery")
    log_auth("recovery_code_sent", ip, email, username)
    return {"ok": True}

@app.post("/api/v1/auth/recovery/verify")
def recovery_verify(payload: RecoveryVerifyReq, request: Request, db: Session = Depends(get_db)):
    ip = get_client_ip(request)
    email = normalize_email(str(payload.email))
    username = payload.username.strip()
    otp_hash = hmac_sha256(OTP_SECRET, f"{email}|recovery|{payload.code}")
    otp_row = db.execute(select(OtpCode).where(and_(OtpCode.email == email, OtpCode.purpose == "recovery", OtpCode.consumed == 0, OtpCode.expires_at >= now_utc(), OtpCode.otp_hash == otp_hash))).scalar_one_or_none()
    if not otp_row: raise HTTPException(400, "invalid code")
    otp_row.consumed = 1
    user = db.execute(select(User).where(and_(User.email == email, User.username == username))).scalar_one()
    raw_token = secrets.token_urlsafe(48)
    db.add(PasswordResetToken(user_id=user.id, token_hash=hmac_sha256(APP_SECRET, raw_token), expires_at=now_utc() + timedelta(minutes=30)))
    db.commit()
    log_auth("recovery_verify_success", ip, email, username)
    return {"ok": True, "reset_token": raw_token}

@app.post("/api/v1/auth/recovery/reset-password")
def recovery_reset_password(payload: ResetPasswordReq, request: Request, db: Session = Depends(get_db)):
    ip = get_client_ip(request)
    validate_password_strength(payload.new_password)
    t_hash = hmac_sha256(APP_SECRET, payload.token)
    token_row = db.execute(select(PasswordResetToken).where(and_(PasswordResetToken.token_hash == t_hash, PasswordResetToken.consumed == 0, PasswordResetToken.expires_at >= now_utc()))).scalar_one_or_none()
    if not token_row: raise HTTPException(400, "invalid token")
    user = db.execute(select(User).where(User.id == token_row.user_id)).scalar_one()
    user.password_hash = hash_password(payload.new_password)
    token_row.consumed = 1
    db.commit()
    log_auth("password_reset_success", ip, user.email, user.username)
    return {"ok": True}

@app.get("/health")
def health_check(): return {"ok": True, "env": APP_ENV}

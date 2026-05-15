import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import fakeredis
import httpx
import redis.asyncio as redis
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

try:
    from dotenv import load_dotenv

    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
except ImportError:
    pass

try:
    from google.auth.transport.requests import Request as GoogleAuthRequest
    from google.oauth2 import service_account
except ImportError:
    GoogleAuthRequest = None
    service_account = None


def env_flag(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def validate_positive_int(name: str, fallback: int, minimum: int = 1) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        value = fallback
    else:
        try:
            value = int(raw_value)
        except ValueError as exc:
            raise RuntimeError(f"{name} must be an integer.") from exc

    if value < minimum:
        raise RuntimeError(f"{name} must be at least {minimum}.")
    return value


def safe_console_print(message: object) -> None:
    line = str(message)
    try:
        print(line)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        print(line.encode(encoding, errors="backslashreplace").decode(encoding))


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def trim_text(value: object, max_length: int = 240) -> str:
    text = str(value)
    return text if len(text) <= max_length else f"{text[: max_length - 1]}..."


def parse_json_env(raw_value: str, env_name: str) -> dict[str, object]:
    candidate = raw_value.strip()
    if not candidate:
        raise RuntimeError(f"{env_name} is empty.")

    payload_text = candidate
    if not candidate.startswith("{"):
        try:
            payload_text = base64.b64decode(candidate).decode("utf-8")
        except Exception:
            payload_text = candidate

    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{env_name} must be valid JSON or base64-encoded JSON.") from exc

    if not isinstance(payload, dict):
        raise RuntimeError(f"{env_name} must contain a JSON object.")
    return payload


# --- Configuration ---
DEFAULT_COUNTRY_CODE = os.getenv("DEFAULT_COUNTRY_CODE", "855").lstrip("+")
DEV_OTP_MODE = env_flag("DEV_OTP_MODE", False)
OTP_PROVIDER = os.getenv("OTP_PROVIDER", "dev").strip().lower()
REDIS_URL = os.getenv("REDIS_URL", "").strip()
REDIS_HOST = os.getenv("REDIS_HOST", "").strip()
REDIS_PORT = os.getenv("REDIS_PORT", "").strip()
USE_FAKE_REDIS = env_flag("USE_FAKE_REDIS", DEV_OTP_MODE)
OTP_TTL_SECONDS = validate_positive_int("OTP_TTL_SECONDS", 300)
OTP_LENGTH = validate_positive_int("OTP_LENGTH", 6)
VERIFY_OTP_MAX_ATTEMPTS = validate_positive_int("VERIFY_OTP_MAX_ATTEMPTS", 5)
REQUEST_OTP_COOLDOWN_SECONDS = validate_positive_int("REQUEST_OTP_COOLDOWN_SECONDS", 60)
ADMIN_DASHBOARD_ENABLED = env_flag("ADMIN_DASHBOARD_ENABLED", True)
ADMIN_DASHBOARD_USERNAME = os.getenv("ADMIN_DASHBOARD_USERNAME", "").strip()
ADMIN_DASHBOARD_PASSWORD = os.getenv("ADMIN_DASHBOARD_PASSWORD", "").strip()
ADMIN_DASHBOARD_REALM = os.getenv("ADMIN_DASHBOARD_REALM", "OTP Admin Monitor").strip() or "OTP Admin Monitor"
ADMIN_DASHBOARD_AUTH_CONFIGURED = bool(ADMIN_DASHBOARD_USERNAME and ADMIN_DASHBOARD_PASSWORD)
ADMIN_LOGIN_RATE_LIMIT = os.getenv("ADMIN_LOGIN_RATE_LIMIT", "10/minute").strip()
ADMIN_ROLE_SUPER_ADMIN = "super_admin"
ADMIN_ROLE_STAFF = "staff"
ADMIN_SESSION_COOKIE_NAME = os.getenv("ADMIN_SESSION_COOKIE_NAME", "otp_admin_session").strip() or "otp_admin_session"
ADMIN_SESSION_DURATION_SECONDS = validate_positive_int("ADMIN_SESSION_DURATION_SECONDS", 28800)
ADMIN_SESSION_COOKIE_SECURE = env_flag("ADMIN_SESSION_COOKIE_SECURE", not DEV_OTP_MODE)
REDIS_MAX_CONNECTIONS = validate_positive_int("REDIS_MAX_CONNECTIONS", 10)
REDIS_STARTUP_RETRIES = validate_positive_int("REDIS_STARTUP_RETRIES", 5)
REDIS_STARTUP_RETRY_DELAY_SECONDS = validate_positive_int("REDIS_STARTUP_RETRY_DELAY_SECONDS", 2)
EXTERNAL_API_HEADER_NAME = os.getenv("EXTERNAL_API_HEADER_NAME", "X-API-Key").strip() or "X-API-Key"
EXTERNAL_API_KEYS = [
    key.strip()
    for key in os.getenv("EXTERNAL_API_KEYS", "").split(",")
    if key.strip()
]
EXTERNAL_API_RATE_LIMIT = os.getenv("EXTERNAL_API_RATE_LIMIT", "60/minute").strip()
REQUEST_OTP_RATE_LIMIT = os.getenv(
    "REQUEST_OTP_RATE_LIMIT",
    "30/minute" if DEV_OTP_MODE else "1/minute",
).strip()
VERIFY_OTP_RATE_LIMIT = os.getenv(
    "VERIFY_OTP_RATE_LIMIT",
    "60/minute" if DEV_OTP_MODE else "10/minute",
).strip()
METRICS_EVENT_LIMIT = validate_positive_int("METRICS_EVENT_LIMIT", 200)
METRICS_TOP_LIMIT = validate_positive_int("METRICS_TOP_LIMIT", 10)
PROVIDER_FAILURE_WINDOW_SECONDS = validate_positive_int("PROVIDER_FAILURE_WINDOW_SECONDS", 900)
PLASGATE_SECRET_KEY = os.getenv("PLASGATE_SECRET_KEY", "").strip()
PLASGATE_PRIVATE_KEY = os.getenv("PLASGATE_PRIVATE_KEY", "").strip()
PLASGATE_SENDER = os.getenv("PLASGATE_SENDER", "PlasGateUAT").strip()
GOOGLE_SHEETS_BACKUP_ENABLED = env_flag("GOOGLE_SHEETS_BACKUP_ENABLED", False)
GOOGLE_SHEETS_BACKUP_STRICT = env_flag("GOOGLE_SHEETS_BACKUP_STRICT", False)
GOOGLE_SHEETS_BACKUP_SPREADSHEET_ID = os.getenv("GOOGLE_SHEETS_BACKUP_SPREADSHEET_ID", "").strip()
GOOGLE_SHEETS_BACKUP_SHEET_NAME = os.getenv("GOOGLE_SHEETS_BACKUP_SHEET_NAME", "Customers").strip() or "Customers"
GOOGLE_SHEETS_BACKUP_DASHBOARD_SHEET_NAME = os.getenv(
    "GOOGLE_SHEETS_BACKUP_DASHBOARD_SHEET_NAME",
    "Dashboard",
).strip() or "Dashboard"
GOOGLE_SHEETS_SERVICE_ACCOUNT_JSON = os.getenv("GOOGLE_SHEETS_SERVICE_ACCOUNT_JSON", "").strip()
GOOGLE_SHEETS_SERVICE_ACCOUNT_FILE = os.getenv("GOOGLE_SHEETS_SERVICE_ACCOUNT_FILE", "").strip()
GOOGLE_SHEETS_BACKUP_TIMEOUT_SECONDS = validate_positive_int("GOOGLE_SHEETS_BACKUP_TIMEOUT_SECONDS", 15)
GOOGLE_SHEETS_BACKUP_INTERVAL_SECONDS = validate_positive_int("GOOGLE_SHEETS_BACKUP_INTERVAL_SECONDS", 300)
GOOGLE_SHEETS_SCOPE = "https://www.googleapis.com/auth/spreadsheets"
APP_VERSION_FILE = Path(__file__).resolve().parent / "VERSION"


def load_app_version() -> str:
    env_version = os.getenv("APP_VERSION", "").strip()
    if env_version:
        return env_version
    try:
        file_version = APP_VERSION_FILE.read_text(encoding="utf-8").strip()
        if file_version:
            return file_version
    except OSError:
        pass
    return "v0.0.1"


APP_VERSION = load_app_version()

if OTP_LENGTH != 6:
    raise RuntimeError("OTP_LENGTH must be 6 to match the current client validation.")


# --- Metrics Keys ---
SUMMARY_METRICS_KEY = "otp_metrics:summary"
PHONE_REQUESTS_KEY = "otp_metrics:phone:requests"
PHONE_VERIFY_FAIL_KEY = "otp_metrics:phone:verify_fail"
PHONE_VERIFY_SUCCESS_KEY = "otp_metrics:phone:verify_success"
RECENT_EVENTS_KEY = "otp_metrics:events"
PROVIDER_METRICS_PREFIX = "otp_metrics:provider:"
CUSTOMER_RECORDS_KEY = "otp_data:customers"
ADMIN_USERS_KEY = "otp_admin:users"
ADMIN_SESSION_PREFIX = "otp_admin:session:"
ADMIN_SESSION_INDEX_PREFIX = "otp_admin:session_index:"
LEGACY_CUSTOMERS_FILE = Path(__file__).resolve().parent / "data" / "customers.json"
BACKUP_EXPORT_DIR = Path(__file__).resolve().parent / "data" / "backups"
BACKUP_EXPORT_FILE = BACKUP_EXPORT_DIR / "latest-backup.json"


# --- Rate Limiter Setup ---
limiter = Limiter(key_func=get_remote_address, default_limits=["10/minute"])


async def close_redis_client(redis_client: redis.Redis) -> None:
    close_method = getattr(redis_client, "aclose", None) or getattr(redis_client, "close", None)
    if close_method is not None:
        result = close_method()
        if asyncio.iscoroutine(result):
            await result


async def warm_redis_client(redis_client: redis.Redis) -> bool:
    delay = float(REDIS_STARTUP_RETRY_DELAY_SECONDS)
    for attempt in range(1, REDIS_STARTUP_RETRIES + 1):
        try:
            await redis_client.ping()
            return True
        except (redis.ConnectionError, redis.TimeoutError, asyncio.TimeoutError, OSError) as exc:
            safe_console_print(f"[redis] startup ping failed ({attempt}/{REDIS_STARTUP_RETRIES}): {trim_text(exc)}")
            if attempt < REDIS_STARTUP_RETRIES:
                await asyncio.sleep(delay)
                delay = min(delay * 2, 15.0)
    return False


# --- Redis Connection Lifespan ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    backup_task: asyncio.Task | None = None
    if USE_FAKE_REDIS:
        redis_client = fakeredis.FakeAsyncRedis(decode_responses=True)
        redis_backend = "fakeredis"
    else:
        redis_url = REDIS_URL
        if not redis_url and REDIS_HOST and REDIS_PORT:
            redis_url = f"redis://{REDIS_HOST}:{REDIS_PORT}"
        if not redis_url:
            raise RuntimeError(
                "Redis connection settings are missing. Set REDIS_URL or provide REDIS_HOST and REDIS_PORT when USE_FAKE_REDIS is false."
            )
        redis_client = redis.from_url(
            redis_url,
            decode_responses=True,
            max_connections=REDIS_MAX_CONNECTIONS,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30,
        )
        await warm_redis_client(redis_client)
        redis_backend = "redis"

    app.state.redis = redis_client
    app.state.redis_backend = redis_backend

    try:
        await sync_seed_admin_users(redis_client)
    except Exception as exc:
        safe_console_print(f"[redis] unable to seed admin users at startup: {trim_text(exc)}")

    if GOOGLE_SHEETS_BACKUP_ENABLED and GOOGLE_SHEETS_BACKUP_STRICT and not is_google_sheets_backup_ready():
        raise RuntimeError(
            "Google Sheets backup is enabled in strict mode but configuration or dependencies are missing."
        )

    print(
        "--- OTP CONFIG --- "
        f"app_version={APP_VERSION}, "
        f"provider={OTP_PROVIDER}, "
        f"dev_mode={DEV_OTP_MODE}, "
        f"redis_backend={redis_backend}, "
        f"request_limit={REQUEST_OTP_RATE_LIMIT}, "
        f"verify_limit={VERIFY_OTP_RATE_LIMIT}, "
        f"cooldown_seconds={REQUEST_OTP_COOLDOWN_SECONDS}, "
        f"max_attempts={VERIFY_OTP_MAX_ATTEMPTS}, "
        f"metrics_event_limit={METRICS_EVENT_LIMIT}, "
        f"admin_dashboard_enabled={ADMIN_DASHBOARD_ENABLED}, "
        f"admin_dashboard_auth_configured={ADMIN_DASHBOARD_AUTH_CONFIGURED}, "
        f"admin_cookie_secure={ADMIN_SESSION_COOKIE_SECURE}, "
        f"google_sheets_backup_enabled={GOOGLE_SHEETS_BACKUP_ENABLED}, "
        f"google_sheets_backup_ready={is_google_sheets_backup_ready()}, "
        f"infobip_key_present={'yes' if bool(os.getenv('INFOBIP_API_KEY')) else 'no'}, "
        f"twilio_sid_present={'yes' if bool(os.getenv('TWILIO_ACCOUNT_SID')) else 'no'}"
    )

    backup_task = asyncio.create_task(run_backup_loop(redis_client, redis_backend))

    try:
        yield
    finally:
        if backup_task is not None:
            backup_task.cancel()
            try:
                await backup_task
            except asyncio.CancelledError:
                pass
        await close_redis_client(redis_client)


# --- FastAPI App Initialization ---
app = FastAPI(
    title="OTP Service API",
    description="A simple API to request and verify One-Time Passwords (OTPs).",
    version="1.3.0",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


@app.middleware("http")
async def disable_cache(request: Request, call_next):
    if ADMIN_DASHBOARD_ENABLED and is_protected_admin_path(request.url.path):
        if not ADMIN_DASHBOARD_AUTH_CONFIGURED:
            return build_admin_unavailable_response()
        redis_client = getattr(request.app.state, "redis", None)
        if redis_client is None:
            return build_admin_storage_unavailable_response()
        try:
            if not await is_admin_authenticated(request, redis_client):
                return build_admin_auth_response()
        except (redis.ConnectionError, redis.TimeoutError, asyncio.TimeoutError, OSError) as exc:
            safe_console_print(f"[admin] auth lookup failed: {trim_text(exc)}")
            return build_admin_storage_unavailable_response()

    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-App-Version"] = APP_VERSION
    return response


async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    redis_client = getattr(request.app.state, "redis", None)
    if redis_client is not None and (
        request.url.path in {"/request-otp", "/verify-otp", "/api/request-otp", "/api/verify-otp"}
        or request.url.path.startswith("/api/v1/")
    ):
        await increment_summary_fields(
            redis_client,
            {
                "rate_limit_blocked_total": 1,
                f"{request.url.path.strip('/').replace('-', '_')}_rate_limited_total": 1,
            },
        )
        await append_metric_event(
            redis_client,
            {
                "type": "rate_limited",
                "path": request.url.path,
                "status": "blocked",
                "client_ip": get_remote_address(request),
                "recorded_at": utc_now_iso(),
            },
        )

    return JSONResponse(
        status_code=429,
        content={"detail": "Too many OTP requests. Please wait a moment and try again."},
    )


app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)


# --- Pydantic Models for Request/Response ---
class OTPRequest(BaseModel):
    phone: str = Field(..., description="The user's phone number.", examples=["1234567890"])
    lang: str = Field(default="th", description="Language preference (en, kh, th).", examples=["th"])


class OTPVerify(BaseModel):
    phone: str = Field(..., description="The user's phone number.", examples=["1234567890"])
    otp: str = Field(..., description="The 6-digit OTP received by the user.", examples=["123456"])
    lang: str = Field(default="th", description="Language preference (en, kh, th).", examples=["th"])


class StaffAssistedOTPRequest(BaseModel):
    phone: str = Field(..., description="Customer phone number in local format.", examples=["0812345678"])
    lang: str = Field(default="th", description="Language preference (en, kh, th).", examples=["th"])


class StaffAssistedOTPVerify(BaseModel):
    phone: str = Field(..., description="Customer phone number in local format.", examples=["0812345678"])
    otp: str = Field(..., description="The 6-digit OTP received by the customer.", examples=["123456"])
    lang: str = Field(default="th", description="Language preference (en, kh, th).", examples=["th"])


class AdminLoginRequest(BaseModel):
    username: str = Field(..., min_length=1, examples=["Admin"])
    password: str = Field(..., min_length=1, examples=["icash123"])
    next_path: str = Field(default="/ops.html", examples=["/ops.html"])


class SuccessResponse(BaseModel):
    message: str


class AdminLoginResponse(BaseModel):
    message: str
    next_path: str
    role: str | None = None


class AdminSessionResponse(BaseModel):
    authenticated: bool
    username: str | None = None
    role: str | None = None
    permissions: dict[str, bool] = Field(default_factory=dict)
    admin_dashboard_enabled: bool
    admin_dashboard_auth_configured: bool


class AdminUserRecord(BaseModel):
    username: str
    role: str
    origin: str = "manual"
    created_at: str
    updated_at: str
    active: bool = True


class AdminUsersResponse(BaseModel):
    users: list[AdminUserRecord]


class AdminCreateUserRequest(BaseModel):
    username: str = Field(..., min_length=1, examples=["staff01"])
    password: str = Field(..., min_length=6, examples=["ChangeMe123!"])


class AdminCreateUserResponse(BaseModel):
    message: str
    user: AdminUserRecord


class AdminUpdateUserPasswordRequest(BaseModel):
    password: str = Field(..., min_length=6, examples=["NewStrongPass123!"])


class AdminUpdateUserPasswordResponse(BaseModel):
    message: str
    user: AdminUserRecord


class StaffAssistedRequestResponse(BaseModel):
    status: str
    expires_in: int


class StaffAssistedVerifyResponse(BaseModel):
    status: str
    message: str


class HealthResponse(BaseModel):
    status: str
    app_version: str
    provider: str
    dev_mode: bool
    redis_backend: str
    redis_status: str = "ok"
    admin_dashboard_enabled: bool
    admin_dashboard_auth_configured: bool


class CustomerRecord(BaseModel):
    id: str = Field(..., min_length=1, examples=["CUS-001"])
    name: str = Field(..., min_length=1, examples=["Sokha Chan"])
    phone_number: str = Field(..., min_length=1, examples=["0971234567"])
    otp: str = Field(default="", examples=["123456"])
    timestamp: str = Field(default_factory=utc_now_iso, examples=["2026-05-06T09:18:47Z"])


class CustomerRecordsPayload(BaseModel):
    customers: list[CustomerRecord]


class CustomerRecordsResponse(BaseModel):
    customers: list[CustomerRecord]


class ApiStatusResponse(BaseModel):
    status: str
    api_version: str
    app_version: str
    provider: str
    dev_mode: bool
    external_api_enabled: bool
    redis_backend: str
    redis_status: str = "ok"


class ApiCustomerUpsertRequest(BaseModel):
    id: str = Field(..., min_length=1, examples=["CUS-001"])
    name: str = Field(..., min_length=1, examples=["Sokha Chan"])
    phone_number: str = Field(..., min_length=1, examples=["0971234567"])
    otp: str = Field(default="", examples=["123456"])
    timestamp: str = Field(default="", examples=["2026-05-06T09:18:47Z"])


class ApiCustomerRecordResponse(BaseModel):
    customer: CustomerRecord


class ApiCustomersListResponse(BaseModel):
    customers: list[CustomerRecord]


class ApiOtpRequest(BaseModel):
    phone: str = Field(..., description="Customer phone number in local format.", examples=["0812345678"])
    lang: str = Field(default="en", description="Language preference (en, kh, th).", examples=["en"])


class ApiOtpVerify(BaseModel):
    phone: str = Field(..., description="Customer phone number in local format.", examples=["0812345678"])
    otp: str = Field(..., description="The 6-digit OTP received by the customer.", examples=["123456"])
    lang: str = Field(default="en", description="Language preference (en, kh, th).", examples=["en"])


# --- Helper Functions ---
async def get_redis(request: Request) -> redis.Redis:
    return request.app.state.redis


def is_protected_admin_path(path: str) -> bool:
    return path == "/admin/metrics"


def is_safe_next_path(path: str) -> bool:
    return bool(path) and path.startswith("/") and not path.startswith("//")


def build_admin_auth_response() -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"detail": "Authentication required for the OTP admin monitor."},
        headers={"WWW-Authenticate": f'Basic realm="{ADMIN_DASHBOARD_REALM}"'},
    )


def build_admin_unavailable_response() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"detail": "OTP admin monitor is enabled but credentials are not configured."},
    )


def build_admin_storage_unavailable_response() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"detail": "OTP admin monitor storage is temporarily unavailable."},
    )


def is_external_api_configured() -> bool:
    return bool(EXTERNAL_API_KEYS)


def build_external_api_unavailable_response() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"detail": "External API is not configured. Set EXTERNAL_API_KEYS to enable it."},
    )


def build_external_api_auth_response() -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"detail": "A valid API key is required."},
        headers={"WWW-Authenticate": f'ApiKey header="{EXTERNAL_API_HEADER_NAME}"'},
    )


def hash_admin_password(password: str, salt: bytes | None = None) -> str:
    iterations = 390_000
    salt_bytes = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
    salt_text = base64.urlsafe_b64encode(salt_bytes).decode("ascii").rstrip("=")
    digest_text = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"pbkdf2_sha256${iterations}${salt_text}${digest_text}"


def verify_admin_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations_raw, salt_text, digest_text = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_raw)
        salt_bytes = base64.urlsafe_b64decode(f"{salt_text}===")
        expected_digest = base64.urlsafe_b64decode(f"{digest_text}===")
    except Exception:
        return False

    candidate_digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
    return secrets.compare_digest(candidate_digest, expected_digest)


def build_admin_permissions(role: str) -> dict[str, bool]:
    is_super_admin = role == ADMIN_ROLE_SUPER_ADMIN
    return {
        "can_view_dashboard": is_super_admin,
        "can_manage_users": is_super_admin,
        "can_view_customers": True,
        "can_edit_customers": is_super_admin,
        "can_use_verify": True,
    }


def admin_users_key() -> str:
    return ADMIN_USERS_KEY


def admin_session_key(session_id: str) -> str:
    return f"{ADMIN_SESSION_PREFIX}{session_id}"


def admin_session_index_key(username: str) -> str:
    return f"{ADMIN_SESSION_INDEX_PREFIX}{username.strip().lower()}"


def normalize_admin_user_record(raw_record: object) -> dict[str, str | bool]:
    if not isinstance(raw_record, dict):
        raise ValueError("Admin user record must be an object.")

    username = str(raw_record.get("username", "")).strip()
    role = str(raw_record.get("role", ADMIN_ROLE_STAFF)).strip() or ADMIN_ROLE_STAFF
    origin = str(raw_record.get("origin", "manual")).strip() or "manual"
    password_hash = str(raw_record.get("password_hash", "")).strip()
    created_at = str(raw_record.get("created_at", "")).strip() or utc_now_iso()
    updated_at = str(raw_record.get("updated_at", "")).strip() or created_at
    active = bool(raw_record.get("active", True))
    if not username:
        raise ValueError("Admin username is required.")
    if role not in {ADMIN_ROLE_SUPER_ADMIN, ADMIN_ROLE_STAFF}:
        raise ValueError("Invalid admin role.")
    if not password_hash:
        raise ValueError("Admin password hash is required.")
    return {
        "username": username,
        "role": role,
        "origin": origin,
        "password_hash": password_hash,
        "created_at": created_at,
        "updated_at": updated_at,
        "active": active,
    }


def admin_user_summary(record: dict[str, str | bool]) -> AdminUserRecord:
    return AdminUserRecord(
        username=str(record["username"]),
        role=str(record["role"]),
        origin=str(record["origin"]),
        created_at=str(record["created_at"]),
        updated_at=str(record["updated_at"]),
        active=bool(record["active"]),
    )


async def load_admin_users(redis_client: redis.Redis) -> list[dict[str, str | bool]]:
    raw_users = await redis_client.get(admin_users_key())
    if not raw_users:
        return []

    try:
        parsed_users = json.loads(raw_users)
    except json.JSONDecodeError:
        return []

    if not isinstance(parsed_users, list):
        return []

    normalized_users: list[dict[str, str | bool]] = []
    for raw_user in parsed_users:
        try:
            normalized_users.append(normalize_admin_user_record(raw_user))
        except Exception:
            continue
    return normalized_users


async def save_admin_users(redis_client: redis.Redis, users: list[dict[str, str | bool]]) -> None:
    await redis_client.set(admin_users_key(), json.dumps(users, ensure_ascii=False))


async def revoke_admin_sessions(redis_client: redis.Redis, username: str) -> None:
    index_key = admin_session_index_key(username)
    session_ids = await redis_client.smembers(index_key)
    if session_ids:
        await redis_client.delete(*[admin_session_key(session_id) for session_id in session_ids])
    await redis_client.delete(index_key)


async def remove_admin_session_from_index(redis_client: redis.Redis, username: str, session_id: str) -> None:
    if not username or not session_id:
        return
    await redis_client.srem(admin_session_index_key(username), session_id)


async def sync_seed_admin_users(redis_client: redis.Redis) -> None:
    if not ADMIN_DASHBOARD_AUTH_CONFIGURED:
        return

    users = await load_admin_users(redis_client)
    now = utc_now_iso()
    seed_hash = hash_admin_password(ADMIN_DASHBOARD_PASSWORD)

    seed_username = ADMIN_DASHBOARD_USERNAME.strip()
    seed_username_lower = seed_username.lower()
    seed_created_at = now

    for user in users:
        if str(user.get("username", "")).lower() == seed_username_lower and str(user.get("role")) == ADMIN_ROLE_SUPER_ADMIN:
            seed_created_at = str(user.get("created_at", now))
            break

    users = [
        user
        for user in users
        if str(user.get("username", "")).lower() != seed_username_lower
    ]
    users.append(
        {
            "username": seed_username,
            "role": ADMIN_ROLE_SUPER_ADMIN,
            "origin": "env",
            "password_hash": seed_hash,
            "created_at": seed_created_at,
            "updated_at": now,
            "active": True,
        }
    )

    await save_admin_users(redis_client, users)


async def find_admin_user(redis_client: redis.Redis, username: str) -> dict[str, str | bool] | None:
    normalized_username = username.strip().lower()
    if not normalized_username:
        return None

    for user in await load_admin_users(redis_client):
        if str(user.get("username", "")).lower() == normalized_username and bool(user.get("active", True)):
            return user
    return None


async def authenticate_admin_credentials(
    redis_client: redis.Redis,
    username: str,
    password: str,
) -> dict[str, str | bool] | None:
    user = await find_admin_user(redis_client, username)
    if not user:
        return None

    password_hash = str(user.get("password_hash", ""))
    if not verify_admin_password(password, password_hash):
        return None
    return user


async def create_admin_session(redis_client: redis.Redis, user: dict[str, str | bool]) -> str:
    session_id = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + ADMIN_SESSION_DURATION_SECONDS
    session_payload = {
        "username": str(user["username"]),
        "role": str(user["role"]),
        "created_at": utc_now_iso(),
        "expires_at": expires_at,
    }
    await redis_client.setex(admin_session_key(session_id), ADMIN_SESSION_DURATION_SECONDS, json.dumps(session_payload, ensure_ascii=False))
    await redis_client.sadd(admin_session_index_key(str(user["username"])), session_id)
    return session_id


async def load_admin_session(redis_client: redis.Redis, session_id: str | None) -> dict[str, str | int] | None:
    if not session_id:
        return None

    raw_session = await redis_client.get(admin_session_key(session_id))
    if not raw_session:
        return None

    try:
        session_payload = json.loads(raw_session)
    except json.JSONDecodeError:
        return None

    if not isinstance(session_payload, dict):
        return None

    username = str(session_payload.get("username", "")).strip()
    role = str(session_payload.get("role", "")).strip()
    expires_at = int(session_payload.get("expires_at", 0))
    if not username or role not in {ADMIN_ROLE_SUPER_ADMIN, ADMIN_ROLE_STAFF}:
        return None
    if expires_at < int(time.time()):
        await redis_client.delete(admin_session_key(session_id))
        await remove_admin_session_from_index(redis_client, username, session_id)
        return None

    user = await find_admin_user(redis_client, username)
    if not user or str(user.get("role")) != role:
        await redis_client.delete(admin_session_key(session_id))
        await remove_admin_session_from_index(redis_client, username, session_id)
        return None

    return {
        "username": username,
        "role": role,
        "expires_at": expires_at,
    }


async def get_admin_identity(request: Request, redis_client: redis.Redis) -> dict[str, object] | None:
    session_identity = await load_admin_session(redis_client, request.cookies.get(ADMIN_SESSION_COOKIE_NAME))
    if session_identity:
        user = await find_admin_user(redis_client, str(session_identity["username"]))
        if user:
            return {
                "username": str(user["username"]),
                "role": str(user["role"]),
                "permissions": build_admin_permissions(str(user["role"])),
            }

    auth_header = request.headers.get("Authorization", "")
    if auth_header and auth_header.startswith("Basic "):
        try:
            encoded = auth_header.split(" ", 1)[1].strip()
            decoded = base64.b64decode(encoded).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:
            return None

        user = await authenticate_admin_credentials(redis_client, username, password)
        if user:
            return {
                "username": str(user["username"]),
                "role": str(user["role"]),
                "permissions": build_admin_permissions(str(user["role"])),
            }

    return None


async def is_admin_authenticated(request: Request, redis_client: redis.Redis) -> bool:
    if not ADMIN_DASHBOARD_AUTH_CONFIGURED:
        return False
    return (await get_admin_identity(request, redis_client)) is not None


async def require_admin_request(request: Request, redis_client: redis.Redis) -> dict[str, object]:
    if not ADMIN_DASHBOARD_ENABLED:
        raise HTTPException(status_code=404, detail="OTP admin monitor is disabled.")
    if not ADMIN_DASHBOARD_AUTH_CONFIGURED:
        raise HTTPException(status_code=503, detail="OTP admin monitor is enabled but credentials are not configured.")

    identity = await get_admin_identity(request, redis_client)
    if not identity:
        raise HTTPException(status_code=401, detail="Authentication required for the OTP admin monitor.")
    return identity


async def require_admin_role(
    request: Request,
    redis_client: redis.Redis,
    allowed_roles: set[str],
) -> dict[str, object]:
    identity = await require_admin_request(request, redis_client)
    if str(identity.get("role")) not in allowed_roles:
        raise HTTPException(status_code=403, detail="You do not have permission to access this resource.")
    return identity


async def require_external_api_key(request: Request) -> str:
    if not is_external_api_configured():
        raise HTTPException(status_code=503, detail="External API is not configured.")

    provided_key = request.headers.get(EXTERNAL_API_HEADER_NAME, "").strip()
    if not provided_key:
        raise HTTPException(status_code=401, detail="A valid API key is required.")

    for configured_key in EXTERNAL_API_KEYS:
        if secrets.compare_digest(provided_key, configured_key):
            return configured_key

    raise HTTPException(status_code=401, detail="Invalid API key.")


def default_admin_next_path(role: str) -> str:
    return "/ops.html#dashboard" if role == ADMIN_ROLE_SUPER_ADMIN else "/ops.html#verify-phone"


def resolve_admin_next_path(requested_path: str, role: str) -> str:
    default_path = default_admin_next_path(role)
    if not is_safe_next_path(requested_path):
        return default_path

    if role == ADMIN_ROLE_SUPER_ADMIN:
        if requested_path in {"/ops.html", "/"}:
            return default_path
        return requested_path

    if requested_path in {"/ops.html", "/ops.html#verify-phone", "/ops.html#customers", "/verify-phone.html", "/customers.html"}:
        return requested_path if requested_path != "/ops.html" else default_path

    return default_path


def normalize_customer_record(record: CustomerRecord) -> dict[str, str]:
    return {
        "id": record.id.strip(),
        "name": record.name.strip(),
        "phone_number": record.phone_number.strip(),
        "otp": record.otp.strip(),
        "timestamp": record.timestamp.strip() or utc_now_iso(),
    }


def normalize_api_customer_request(payload: ApiCustomerUpsertRequest) -> CustomerRecord:
    return CustomerRecord(
        id=payload.id.strip(),
        name=payload.name.strip(),
        phone_number=payload.phone_number.strip(),
        otp=payload.otp.strip(),
        timestamp=payload.timestamp.strip() or utc_now_iso(),
    )


async def upsert_customer_record(redis_client: redis.Redis, payload: ApiCustomerUpsertRequest) -> list[dict[str, str]]:
    customer = normalize_api_customer_request(payload)
    current_records = await load_customer_records(redis_client)
    normalized_customer = normalize_customer_record(customer)

    current_records = [
        record
        for record in current_records
        if str(record.get("id", "")).strip().lower() != normalized_customer["id"].lower()
    ]
    current_records.insert(0, normalized_customer)

    saved_records = await save_customer_records(redis_client, [CustomerRecord.model_validate(record) for record in current_records])
    return saved_records


def is_google_sheets_backup_ready() -> bool:
    return bool(
        GOOGLE_SHEETS_BACKUP_SPREADSHEET_ID
        and (GOOGLE_SHEETS_SERVICE_ACCOUNT_JSON or GOOGLE_SHEETS_SERVICE_ACCOUNT_FILE)
        and service_account is not None
        and GoogleAuthRequest is not None
    )


def load_google_service_account_info() -> dict[str, object]:
    if GOOGLE_SHEETS_SERVICE_ACCOUNT_JSON:
        return parse_json_env(GOOGLE_SHEETS_SERVICE_ACCOUNT_JSON, "GOOGLE_SHEETS_SERVICE_ACCOUNT_JSON")

    if GOOGLE_SHEETS_SERVICE_ACCOUNT_FILE:
        try:
            raw_text = Path(GOOGLE_SHEETS_SERVICE_ACCOUNT_FILE).read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError("Unable to read GOOGLE_SHEETS_SERVICE_ACCOUNT_FILE.") from exc
        return parse_json_env(raw_text, "GOOGLE_SHEETS_SERVICE_ACCOUNT_FILE")

    raise RuntimeError(
        "Google Sheets backup requires GOOGLE_SHEETS_SERVICE_ACCOUNT_JSON or "
        "GOOGLE_SHEETS_SERVICE_ACCOUNT_FILE."
    )


def get_google_sheets_access_token() -> str:
    if service_account is None or GoogleAuthRequest is None:
        raise RuntimeError("Google Sheets backup dependencies are not installed.")

    if not GOOGLE_SHEETS_BACKUP_SPREADSHEET_ID:
        raise RuntimeError("GOOGLE_SHEETS_BACKUP_SPREADSHEET_ID is required.")

    credentials = service_account.Credentials.from_service_account_info(
        load_google_service_account_info(),
        scopes=[GOOGLE_SHEETS_SCOPE],
    )
    credentials.refresh(GoogleAuthRequest())
    if not credentials.token:
        raise RuntimeError("Unable to obtain a Google Sheets access token.")
    return credentials.token


def build_google_sheet_range(sheet_name: str, cell_range: str) -> str:
    escaped_name = sheet_name.replace("'", "''")
    return f"'{escaped_name}'!{cell_range}"


def google_sheet_column_name(index: int) -> str:
    if index < 1:
        raise ValueError("Google Sheet column index must be positive.")

    column = ""
    while index > 0:
        index, remainder = divmod(index - 1, 26)
        column = chr(65 + remainder) + column
    return column


def build_google_sheet_payload(headers: list[str], rows: list[list[object]]) -> list[list[str]]:
    payload = [headers]
    for row in rows:
        payload.append(["" if value is None else str(value) for value in row])
    return payload


def build_customer_sheet_rows(records: list[dict[str, str]]) -> list[list[object]]:
    return [
        [
            record.get("id", ""),
            record.get("name", ""),
            record.get("phone_number", ""),
            record.get("otp", ""),
            record.get("timestamp", ""),
        ]
        for record in records
    ]


def build_dashboard_sheet_rows(snapshot: dict) -> list[list[object]]:
    generated_at = snapshot.get("generated_at", "")
    rows: list[list[object]] = []

    service = snapshot.get("service") or {}
    for key, value in service.items():
        rows.append(["service", key, value, generated_at, ""])

    summary = snapshot.get("summary") or {}
    for key, value in summary.items():
        rows.append(["summary", key, value, generated_at, ""])

    phones = snapshot.get("phones") or {}
    for section_name, phone_rows in phones.items():
        for index, phone_row in enumerate(phone_rows or [], start=1):
            if isinstance(phone_row, dict):
                rows.append(
                    [
                        section_name,
                        phone_row.get("phone", f"row-{index}"),
                        phone_row.get("count", 0),
                        generated_at,
                        json.dumps(phone_row, ensure_ascii=False),
                    ]
                )

    for provider in snapshot.get("providers") or []:
        if not isinstance(provider, dict):
            continue
        rows.append(
            [
                "provider",
                provider.get("provider", ""),
                provider.get("health", ""),
                provider.get("updated_at", generated_at),
                json.dumps(provider, ensure_ascii=False),
            ]
        )

    for event in snapshot.get("recent_events") or []:
        if not isinstance(event, dict):
            continue
        rows.append(
            [
                "recent_event",
                event.get("type", ""),
                event.get("status", ""),
                event.get("recorded_at", generated_at),
                json.dumps(event, ensure_ascii=False),
            ]
        )

    return rows


def build_backup_export_payload(customers: list[dict[str, str]], dashboard_snapshot: dict) -> dict:
    return {
        "generated_at": utc_now_iso(),
        "customers": customers,
        "dashboard": dashboard_snapshot,
    }


def write_local_backup_export(export_payload: dict) -> None:
    BACKUP_EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_EXPORT_FILE.write_text(
        json.dumps(export_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def extract_http_error_detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        text = response.text.strip()
        return text or f"HTTP {response.status_code}"

    if isinstance(payload, dict):
        error_payload = payload.get("error")
        if isinstance(error_payload, dict):
            message = error_payload.get("message")
            if message:
                return str(message)
        detail = payload.get("detail")
        if detail:
            return str(detail)

    text = response.text.strip()
    return text or f"HTTP {response.status_code}"


async def sync_customer_records_to_google_sheets(records: list[dict[str, str]]) -> None:
    if not GOOGLE_SHEETS_BACKUP_ENABLED:
        return

    if not is_google_sheets_backup_ready():
        raise RuntimeError("Google Sheets backup is enabled but not fully configured.")

    await sync_google_sheet_table(
        sheet_name=GOOGLE_SHEETS_BACKUP_SHEET_NAME,
        headers=["ID", "Name", "PhoneNumber", "OTP", "Timestamp"],
        rows=build_customer_sheet_rows(records),
    )


async def sync_dashboard_snapshot_to_google_sheets(snapshot: dict) -> None:
    if not GOOGLE_SHEETS_BACKUP_ENABLED:
        return

    if not is_google_sheets_backup_ready():
        raise RuntimeError("Google Sheets backup is enabled but not fully configured.")

    await sync_google_sheet_table(
        sheet_name=GOOGLE_SHEETS_BACKUP_DASHBOARD_SHEET_NAME,
        headers=["Section", "Name", "Value", "UpdatedAt", "Details"],
        rows=build_dashboard_sheet_rows(snapshot),
    )


async def sync_google_sheet_table(sheet_name: str, headers: list[str], rows: list[list[object]]) -> None:
    token = await asyncio.to_thread(get_google_sheets_access_token)
    payload = build_google_sheet_payload(headers, rows)
    column_count = max(len(headers), 1)
    last_column = google_sheet_column_name(column_count)
    last_row = max(len(payload), 1)
    clear_range = build_google_sheet_range(sheet_name, f"A:{last_column}")
    update_range = build_google_sheet_range(sheet_name, f"A1:{last_column}{last_row}")
    request_headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    timeout = httpx.Timeout(GOOGLE_SHEETS_BACKUP_TIMEOUT_SECONDS)

    async with httpx.AsyncClient(timeout=timeout) as client:
        clear_response = await client.post(
            "https://sheets.googleapis.com/v4/spreadsheets/"
            f"{GOOGLE_SHEETS_BACKUP_SPREADSHEET_ID}/values/{quote(clear_range, safe='')}:clear",
            headers=request_headers,
        )
        if clear_response.is_error:
            raise RuntimeError(
                f"Unable to clear Google Sheet backup range: {extract_http_error_detail(clear_response)}"
            )

        update_response = await client.put(
            "https://sheets.googleapis.com/v4/spreadsheets/"
            f"{GOOGLE_SHEETS_BACKUP_SPREADSHEET_ID}/values/{quote(update_range, safe='')}",
            headers=request_headers,
            params={"valueInputOption": "RAW"},
            json={
                "majorDimension": "ROWS",
                "values": payload,
            },
        )
        if update_response.is_error:
            raise RuntimeError(
                f"Unable to update Google Sheet backup: {extract_http_error_detail(update_response)}"
            )


def load_customer_records_from_legacy_file() -> list[dict[str, str]]:
    if not LEGACY_CUSTOMERS_FILE.exists():
        return []

    try:
        raw_records = json.loads(LEGACY_CUSTOMERS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(raw_records, list):
        return []

    normalized_records: list[dict[str, str]] = []
    for raw_record in raw_records:
        if not isinstance(raw_record, dict):
            continue
        try:
            record = CustomerRecord.model_validate(raw_record)
        except Exception:
            continue
        normalized_records.append(normalize_customer_record(record))
    return normalized_records


async def load_customer_records(redis_client: redis.Redis) -> list[dict[str, str]]:
    raw_records = await redis_client.get(CUSTOMER_RECORDS_KEY)
    if raw_records:
        try:
            parsed_records = json.loads(raw_records)
        except json.JSONDecodeError:
            parsed_records = None
        if isinstance(parsed_records, list):
            normalized_records: list[dict[str, str]] = []
            for raw_record in parsed_records:
                if not isinstance(raw_record, dict):
                    continue
                try:
                    record = CustomerRecord.model_validate(raw_record)
                except Exception:
                    continue
                normalized_records.append(normalize_customer_record(record))
            return normalized_records

    legacy_records = load_customer_records_from_legacy_file()
    if legacy_records:
        await redis_client.set(CUSTOMER_RECORDS_KEY, json.dumps(legacy_records, ensure_ascii=False))
        try:
            LEGACY_CUSTOMERS_FILE.unlink()
        except OSError:
            pass
    return legacy_records


async def save_customer_records(redis_client: redis.Redis, records: list[CustomerRecord]) -> list[dict[str, str]]:
    normalized_records = [normalize_customer_record(record) for record in records]
    await redis_client.set(CUSTOMER_RECORDS_KEY, json.dumps(normalized_records, ensure_ascii=False))
    if LEGACY_CUSTOMERS_FILE.exists():
        try:
            LEGACY_CUSTOMERS_FILE.unlink()
        except OSError:
            pass
    return normalized_records


async def sync_backup_artifacts(
    redis_client: redis.Redis,
    redis_backend: str,
    *,
    customers: list[dict[str, str]] | None = None,
) -> None:
    resolved_customers = customers if customers is not None else await load_customer_records(redis_client)
    dashboard_snapshot = await build_metrics_snapshot_data(redis_backend, redis_client)
    export_payload = build_backup_export_payload(resolved_customers, dashboard_snapshot)
    write_local_backup_export(export_payload)

    if not GOOGLE_SHEETS_BACKUP_ENABLED:
        return

    if not is_google_sheets_backup_ready():
        message = "Google Sheets backup is enabled but not fully configured."
        if GOOGLE_SHEETS_BACKUP_STRICT:
            raise RuntimeError(message)
        safe_console_print(f"[backup] {message}")
        return

    await sync_customer_records_to_google_sheets(resolved_customers)
    await sync_dashboard_snapshot_to_google_sheets(dashboard_snapshot)


async def run_backup_loop(redis_client: redis.Redis, redis_backend: str) -> None:
    while True:
        try:
            await sync_backup_artifacts(redis_client, redis_backend)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            safe_console_print(f"[backup-loop] {trim_text(exc)}")

        try:
            await asyncio.sleep(GOOGLE_SHEETS_BACKUP_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            raise


def generate_otp() -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(OTP_LENGTH))


def generate_ref_code(length: int = 4) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def normalize_phone_number(phone: str) -> str:
    cleaned = re.sub(r"[\s\-().]", "", phone.strip())

    if cleaned.startswith("00"):
        cleaned = f"+{cleaned[2:]}"
    elif cleaned.startswith("0"):
        cleaned = f"+{DEFAULT_COUNTRY_CODE}{cleaned[1:]}"
    elif cleaned.startswith(DEFAULT_COUNTRY_CODE):
        cleaned = f"+{cleaned}"

    if not re.fullmatch(r"\+[1-9]\d{7,14}", cleaned):
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid phone number. Use local format like 0971234567 or "
                f"E.164 format like +{DEFAULT_COUNTRY_CODE}971234567."
            ),
        )

    return cleaned


def validate_otp_format(otp: str) -> str:
    normalized = otp.strip()
    if not re.fullmatch(rf"\d{{{OTP_LENGTH}}}", normalized):
        raise HTTPException(status_code=400, detail=f"OTP must contain exactly {OTP_LENGTH} digits.")
    return normalized


def get_otp_key(phone_number: str) -> str:
    return f"otp:{phone_number}"


def get_otp_attempts_key(phone_number: str) -> str:
    return f"otp_attempts:{phone_number}"


def get_otp_session_key(phone_number: str) -> str:
    return f"otp_session:{phone_number}"


def get_otp_ref_code_key(phone_number: str) -> str:
    return f"otp_ref_code:{phone_number}"


def get_otp_cooldown_key(phone_number: str) -> str:
    return f"otp_cooldown:{phone_number}"


def get_provider_metrics_key(provider_name: str) -> str:
    return f"{PROVIDER_METRICS_PREFIX}{provider_name}"


async def get_remaining_cooldown(redis_client: redis.Redis, phone_number: str) -> int:
    cooldown_ttl = await redis_client.ttl(get_otp_cooldown_key(phone_number))
    return cooldown_ttl if cooldown_ttl and cooldown_ttl > 0 else 0


async def set_request_cooldown(redis_client: redis.Redis, phone_number: str) -> None:
    await redis_client.set(
        get_otp_cooldown_key(phone_number),
        "1",
        ex=REQUEST_OTP_COOLDOWN_SECONDS,
    )


async def store_otp(redis_client: redis.Redis, phone_number: str, otp_code: str) -> None:
    otp_key = get_otp_key(phone_number)
    attempts_key = get_otp_attempts_key(phone_number)

    async with redis_client.pipeline(transaction=True) as pipeline:
        await pipeline.set(otp_key, otp_code, ex=OTP_TTL_SECONDS)
        await pipeline.delete(attempts_key)
        await pipeline.execute()


async def store_ref_code(redis_client: redis.Redis, phone_number: str, ref_code: str) -> None:
    await redis_client.set(get_otp_ref_code_key(phone_number), ref_code, ex=OTP_TTL_SECONDS)


async def clear_otp_state(redis_client: redis.Redis, phone_number: str) -> None:
    await redis_client.delete(
        get_otp_key(phone_number),
        get_otp_attempts_key(phone_number),
        get_otp_session_key(phone_number),
        get_otp_ref_code_key(phone_number),
    )


async def record_failed_attempt(redis_client: redis.Redis, phone_number: str) -> int:
    attempts_key = get_otp_attempts_key(phone_number)
    otp_key = get_otp_key(phone_number)

    current_attempts = await redis_client.incr(attempts_key)
    otp_ttl = await redis_client.ttl(otp_key)
    if otp_ttl and otp_ttl > 0:
        await redis_client.expire(attempts_key, otp_ttl)
    return current_attempts


async def increment_summary_fields(redis_client: redis.Redis, updates: dict[str, int]) -> None:
    async with redis_client.pipeline(transaction=True) as pipeline:
        for field, amount in updates.items():
            await pipeline.hincrby(SUMMARY_METRICS_KEY, field, amount)
        await pipeline.execute()


async def increment_phone_metric(redis_client: redis.Redis, metric_key: str, phone_number: str, amount: int = 1) -> None:
    await redis_client.hincrby(metric_key, phone_number, amount)


async def append_metric_event(redis_client: redis.Redis, payload: dict) -> None:
    event_payload = {"recorded_at": utc_now_iso(), **payload}
    async with redis_client.pipeline(transaction=True) as pipeline:
        await pipeline.lpush(RECENT_EVENTS_KEY, json.dumps(event_payload))
        await pipeline.ltrim(RECENT_EVENTS_KEY, 0, METRICS_EVENT_LIMIT - 1)
        await pipeline.execute()


async def record_request_received(redis_client: redis.Redis, phone_number: str) -> None:
    await increment_summary_fields(redis_client, {"request_total": 1})
    await increment_phone_metric(redis_client, PHONE_REQUESTS_KEY, phone_number)


async def record_request_blocked(redis_client: redis.Redis, phone_number: str, reason: str, detail: str) -> None:
    await increment_summary_fields(redis_client, {"request_blocked_total": 1, f"request_blocked_{reason}_total": 1})
    await append_metric_event(
        redis_client,
        {
            "type": "request_blocked",
            "status": "blocked",
            "reason": reason,
            "phone": phone_number,
            "detail": detail,
        },
    )


async def record_request_completed(
    redis_client: redis.Redis,
    phone_number: str,
    provider_name: str,
    provider_status: str,
    detail: str,
) -> None:
    await increment_summary_fields(redis_client, {"request_completed_total": 1})
    await append_metric_event(
        redis_client,
        {
            "type": "request_completed",
            "status": provider_status,
            "phone": phone_number,
            "provider": provider_name,
            "detail": detail,
        },
    )


async def record_request_failed(redis_client: redis.Redis, phone_number: str, provider_name: str, detail: str) -> None:
    await increment_summary_fields(redis_client, {"request_failed_total": 1})
    await append_metric_event(
        redis_client,
        {
            "type": "request_failed",
            "status": "failure",
            "phone": phone_number,
            "provider": provider_name,
            "detail": detail,
        },
    )


async def record_verify_attempt(redis_client: redis.Redis) -> None:
    await increment_summary_fields(redis_client, {"verify_total": 1})


async def record_verify_failure(redis_client: redis.Redis, phone_number: str, reason: str, detail: str) -> None:
    await increment_summary_fields(redis_client, {"verify_failed_total": 1, f"verify_failed_{reason}_total": 1})
    await increment_phone_metric(redis_client, PHONE_VERIFY_FAIL_KEY, phone_number)
    await append_metric_event(
        redis_client,
        {
            "type": "verify_failed",
            "status": "failure",
            "reason": reason,
            "phone": phone_number,
            "detail": detail,
        },
    )


async def record_verify_success(redis_client: redis.Redis, phone_number: str, detail: str) -> None:
    await increment_summary_fields(redis_client, {"verify_success_total": 1})
    await increment_phone_metric(redis_client, PHONE_VERIFY_SUCCESS_KEY, phone_number)
    await append_metric_event(
        redis_client,
        {
            "type": "verify_success",
            "status": "success",
            "phone": phone_number,
            "detail": detail,
        },
    )


async def record_verify_provider_failure(
    redis_client: redis.Redis,
    phone_number: str,
    provider_name: str,
    detail: str,
) -> None:
    await increment_summary_fields(redis_client, {"verify_failed_total": 1, "verify_failed_provider_total": 1})
    await increment_phone_metric(redis_client, PHONE_VERIFY_FAIL_KEY, phone_number)
    await append_metric_event(
        redis_client,
        {
            "type": "verify_failed",
            "status": "failure",
            "reason": "provider",
            "phone": phone_number,
            "provider": provider_name,
            "detail": detail,
        },
    )


async def record_provider_operation(
    redis_client: redis.Redis,
    provider_name: str,
    operation: str,
    status: str,
    latency_ms: float,
    *,
    phone_number: str | None = None,
    detail: str | None = None,
) -> None:
    provider_key = get_provider_metrics_key(provider_name)
    rounded_latency = round(latency_ms, 2)
    summary_fields = {
        f"provider_{operation}_{status}_total": 1,
    }

    async with redis_client.pipeline(transaction=True) as pipeline:
        await pipeline.hincrby(provider_key, f"{operation}_{status}", 1)
        await pipeline.hincrby(provider_key, f"{operation}_count", 1)
        await pipeline.hincrbyfloat(provider_key, f"{operation}_latency_total_ms", rounded_latency)
        await pipeline.hset(provider_key, mapping={
            f"{operation}_latency_last_ms": rounded_latency,
            "last_operation": operation,
            "last_status": status,
            "updated_at": utc_now_iso(),
        })
        if detail:
            await pipeline.hset(provider_key, "last_detail", trim_text(detail))
        if phone_number:
            await pipeline.hset(provider_key, "last_phone", phone_number)
        if status == "failure":
            await pipeline.hset(provider_key, mapping={"last_error": trim_text(detail or "Provider failure"), "last_error_at": utc_now_iso()})
        else:
            await pipeline.hset(provider_key, "last_success_at", utc_now_iso())
        await pipeline.execute()

    existing_max = await redis_client.hget(provider_key, f"{operation}_latency_max_ms")
    existing_max_value = float(existing_max) if existing_max is not None else 0.0
    if rounded_latency > existing_max_value:
        await redis_client.hset(provider_key, f"{operation}_latency_max_ms", rounded_latency)

    await increment_summary_fields(redis_client, summary_fields)
    await append_metric_event(
        redis_client,
        {
            "type": "provider_operation",
            "status": status,
            "provider": provider_name,
            "operation": operation,
            "phone": phone_number,
            "latency_ms": rounded_latency,
            "detail": detail,
        },
    )


def parse_http_error_detail(exc: HTTPException) -> str:
    if isinstance(exc.detail, str):
        return exc.detail
    return trim_text(exc.detail)


def normalize_ref_code(ref_code: str) -> str:
    normalized = ref_code.strip().upper()
    if not re.fullmatch(r"[A-Z0-9]{4,16}", normalized):
        raise HTTPException(status_code=400, detail="Invalid reference code.")
    return normalized


async def execute_provider_operation(
    redis_client: redis.Redis,
    provider_name: str,
    operation: str,
    phone_number: str,
    action,
):
    started_at = time.perf_counter()
    try:
        result = await action()
        elapsed_ms = (time.perf_counter() - started_at) * 1000
        status = "simulated" if result == "simulated" else "success"
        await record_provider_operation(
            redis_client,
            provider_name,
            operation,
            status,
            elapsed_ms,
            phone_number=phone_number,
            detail="Provider accepted request." if status != "simulated" else "Development-mode simulation.",
        )
        return result
    except HTTPException as exc:
        elapsed_ms = (time.perf_counter() - started_at) * 1000
        await record_provider_operation(
            redis_client,
            provider_name,
            operation,
            "failure",
            elapsed_ms,
            phone_number=phone_number,
            detail=parse_http_error_detail(exc),
        )
        raise
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - started_at) * 1000
        await record_provider_operation(
            redis_client,
            provider_name,
            operation,
            "failure",
            elapsed_ms,
            phone_number=phone_number,
            detail=str(exc),
        )
        raise


async def send_sms(phone: str, message: str) -> str:
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    twilio_phone = os.getenv("TWILIO_PHONE_NUMBER")

    if DEV_OTP_MODE:
        safe_console_print("--- DEVELOPMENT MODE: OTP SMS IS PRINTED HERE ONLY ---")
        safe_console_print(f"To: {phone}")
        safe_console_print(f"Message: {message}")
        safe_console_print("------------------------------------")
        return "simulated"

    if not all([account_sid, auth_token, twilio_phone]):
        safe_console_print("--- TWILIO CREDENTIALS NOT FOUND ---")
        safe_console_print("--- DEVELOPMENT MODE: OTP SMS IS PRINTED HERE ONLY ---")
        safe_console_print(f"To: {phone}")
        safe_console_print(f"Message: {message}")
        safe_console_print("------------------------------------")
        return "simulated"

    try:
        def send_twilio_message():
            from twilio.base.exceptions import TwilioRestException
            from twilio.rest import Client

            try:
                client = Client(account_sid, auth_token)
                return client.messages.create(body=message, from_=twilio_phone, to=phone)
            except TwilioRestException as exc:
                raise HTTPException(status_code=502, detail=f"Twilio Error {exc.code}: {exc.msg}") from exc

        twilio_message = await asyncio.to_thread(send_twilio_message)
        safe_console_print(f"--- SMS sent successfully to {phone} (SID: {twilio_message.sid}) ---")
        return "sent"
    except HTTPException:
        raise
    except Exception as exc:
        safe_console_print("--- FAILED TO SEND SMS ---")
        safe_console_print(f"Error: {exc}")
        raise HTTPException(status_code=500, detail="Failed to send OTP SMS.") from exc


async def send_aws_sns_sms(phone: str, message: str) -> str:
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError

        region_name = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"

        def publish_message():
            client = boto3.client("sns", region_name=region_name)
            return client.publish(
                PhoneNumber=phone,
                Message=message,
                MessageAttributes={
                    "AWS.SNS.SMS.SMSType": {
                        "DataType": "String",
                        "StringValue": "Transactional",
                    }
                },
            )

        response = await asyncio.to_thread(publish_message)
        message_id = response.get("MessageId")
        safe_console_print(f"--- AWS SNS SMS accepted for {phone} (MessageId: {message_id}) ---")
        return "sent"
    except (BotoCoreError, ClientError) as exc:
        error_message = str(exc)
        safe_console_print("--- FAILED TO SEND AWS SNS SMS ---")
        safe_console_print(f"Error: {error_message}")
        raise HTTPException(status_code=502, detail=f"AWS SNS error: {error_message}") from exc


async def send_infobip_sms(phone: str, message: str) -> str:
    api_key = os.getenv("INFOBIP_API_KEY")
    base_url = os.getenv("INFOBIP_BASE_URL", "https://api.infobip.com").strip().rstrip("/")
    sender = os.getenv("INFOBIP_SENDER", "ServiceSMS").strip()

    if not api_key:
        raise HTTPException(status_code=500, detail="Infobip is selected but INFOBIP_API_KEY is missing.")

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{base_url}/sms/3/messages",
                headers={
                    "Authorization": f"App {api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json={
                    "messages": [
                        {
                            "sender": sender,
                            "destinations": [{"to": phone}],
                            "content": {"text": message},
                        }
                    ]
                },
            )

        if response.status_code >= 400:
            error_body = response.text.strip()
            safe_console_print("--- FAILED TO SEND INFOBIP SMS ---")
            safe_console_print(f"Status: {response.status_code}")
            safe_console_print(f"Body: {error_body}")
            raise HTTPException(status_code=502, detail=f"Infobip error {response.status_code}: {error_body}")

        payload = response.json()
        message_id = None
        messages = payload.get("messages") or []
        if messages:
            message_id = messages[0].get("messageId")
        safe_console_print(f"--- INFOBIP SMS accepted for {phone} (MessageId: {message_id}) ---")
        return "sent"
    except HTTPException:
        raise
    except Exception as exc:
        error_message = str(exc)
        safe_console_print("--- FAILED TO SEND INFOBIP SMS ---")
        safe_console_print(f"Error: {error_message}")
        raise HTTPException(status_code=502, detail=f"Infobip error: {error_message}") from exc


async def send_plasgate_sms(phone: str, message: str) -> str:
    secret_key = PLASGATE_SECRET_KEY
    private_key = PLASGATE_PRIVATE_KEY
    sender = PLASGATE_SENDER

    if not secret_key or not private_key:
        raise HTTPException(
            status_code=500,
            detail="Plasgate is selected but PLASGATE_SECRET_KEY or PLASGATE_PRIVATE_KEY is missing.",
        )

    # Plasgate expects the phone number without the '+' prefix for some endpoints, 
    # but their docs show '855...' format. Let's strip the '+' if present.
    target_phone = phone.lstrip("+")

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"https://cloudapi.plasgate.com/rest/send?private_key={private_key}",
                headers={
                    "X-Secret": secret_key,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json={
                    "sender": sender,
                    "to": target_phone,
                    "content": message,
                },
            )

        if response.status_code >= 400:
            error_body = response.text.strip()
            safe_console_print("--- FAILED TO SEND PLASGATE SMS ---")
            safe_console_print(f"Status: {response.status_code}")
            safe_console_print(f"Body: {error_body}")
            raise HTTPException(status_code=502, detail=f"Plasgate error {response.status_code}: {error_body}")

        safe_console_print(f"--- PLASGATE SMS accepted for {phone} ---")
        return "sent"
    except HTTPException:
        raise
    except Exception as exc:
        error_message = str(exc)
        safe_console_print("--- FAILED TO SEND PLASGATE SMS ---")
        safe_console_print(f"Error: {error_message}")
        raise HTTPException(status_code=502, detail=f"Plasgate error: {error_message}") from exc


async def create_plivo_verify_session(phone: str) -> str:
    auth_id = os.getenv("PLIVO_AUTH_ID")
    auth_token = os.getenv("PLIVO_AUTH_TOKEN")
    verify_app_uuid = os.getenv("PLIVO_VERIFY_APP_UUID")

    if not all([auth_id, auth_token, verify_app_uuid]):
        raise HTTPException(
            status_code=500,
            detail="Plivo is selected but PLIVO_AUTH_ID, PLIVO_AUTH_TOKEN, or PLIVO_VERIFY_APP_UUID is missing.",
        )

    try:
        def create_session():
            import plivo

            client = plivo.RestClient(auth_id, auth_token)
            return client.verify_session.create(
                recipient=phone,
                app_uuid=verify_app_uuid,
                channel="sms",
            )

        response = await asyncio.to_thread(create_session)
        session_uuid = getattr(response, "session_uuid", None)
        if not session_uuid:
            raise HTTPException(status_code=502, detail="Plivo Verify did not return a session UUID.")
        return session_uuid
    except HTTPException:
        raise
    except Exception as exc:
        error_message = str(exc)
        safe_console_print("--- FAILED TO CREATE PLIVO VERIFY SESSION ---")
        safe_console_print(f"Error: {error_message}")
        raise HTTPException(status_code=502, detail=f"Plivo Verify error: {error_message}") from exc


async def validate_plivo_verify_session(session_uuid: str, otp: str) -> str:
    auth_id = os.getenv("PLIVO_AUTH_ID")
    auth_token = os.getenv("PLIVO_AUTH_TOKEN")

    if not all([auth_id, auth_token]):
        raise HTTPException(
            status_code=500,
            detail="Plivo validation is selected but PLIVO_AUTH_ID or PLIVO_AUTH_TOKEN is missing.",
        )

    try:
        def validate_session():
            import plivo

            client = plivo.RestClient(auth_id, auth_token)
            return client.verify_session.validate(session_uuid=session_uuid, otp=otp)

        response = await asyncio.to_thread(validate_session)
        return getattr(response, "message", "OTP verified successfully.")
    except HTTPException:
        raise
    except Exception as exc:
        error_message = str(exc)
        safe_console_print("--- FAILED TO VALIDATE PLIVO VERIFY SESSION ---")
        safe_console_print(f"Error: {error_message}")
        raise HTTPException(status_code=400, detail=f"Plivo Verify validation failed: {error_message}") from exc


async def get_top_phone_entries(redis_client: redis.Redis, metric_key: str, limit: int = METRICS_TOP_LIMIT) -> list[dict]:
    raw_metrics = await redis_client.hgetall(metric_key)
    ranked = sorted(
        (
            {"phone": phone, "count": int(count)}
            for phone, count in raw_metrics.items()
        ),
        key=lambda item: (-item["count"], item["phone"]),
    )
    return ranked[:limit]


def compute_provider_health(provider_stats: dict) -> str:
    last_status = provider_stats.get("last_status", "unknown")
    updated_at = provider_stats.get("updated_at")

    if last_status == "failure":
        if updated_at:
            try:
                updated_ts = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                seconds_since_update = (datetime.now(timezone.utc) - updated_ts).total_seconds()
                if seconds_since_update <= PROVIDER_FAILURE_WINDOW_SECONDS:
                    return "failing"
            except ValueError:
                return "failing"
        return "degraded"

    if last_status in {"success", "simulated"}:
        return "healthy"

    return "unknown"


async def get_provider_metrics(redis_client: redis.Redis) -> list[dict]:
    providers = []
    async for provider_key in redis_client.scan_iter(match=f"{PROVIDER_METRICS_PREFIX}*"):
        provider_name = provider_key.replace(PROVIDER_METRICS_PREFIX, "", 1)
        raw_stats = await redis_client.hgetall(provider_key)
        provider_stats = {
            "provider": provider_name,
            "last_operation": raw_stats.get("last_operation"),
            "last_status": raw_stats.get("last_status"),
            "last_phone": raw_stats.get("last_phone"),
            "last_detail": raw_stats.get("last_detail"),
            "last_error": raw_stats.get("last_error"),
            "last_error_at": raw_stats.get("last_error_at"),
            "last_success_at": raw_stats.get("last_success_at"),
            "updated_at": raw_stats.get("updated_at"),
            "health": "unknown",
            "operations": {},
        }

        for operation in ("send", "verify"):
            count = int(float(raw_stats.get(f"{operation}_count", 0) or 0))
            total_latency = float(raw_stats.get(f"{operation}_latency_total_ms", 0) or 0)
            provider_stats["operations"][operation] = {
                "count": count,
                "success": int(float(raw_stats.get(f"{operation}_success", 0) or 0)),
                "failure": int(float(raw_stats.get(f"{operation}_failure", 0) or 0)),
                "simulated": int(float(raw_stats.get(f"{operation}_simulated", 0) or 0)),
                "latency_last_ms": round(float(raw_stats.get(f"{operation}_latency_last_ms", 0) or 0), 2),
                "latency_max_ms": round(float(raw_stats.get(f"{operation}_latency_max_ms", 0) or 0), 2),
                "latency_avg_ms": round(total_latency / count, 2) if count else 0,
            }

        provider_stats["health"] = compute_provider_health(provider_stats)
        providers.append(provider_stats)

    providers.sort(key=lambda item: item["provider"])
    return providers


async def get_recent_events(redis_client: redis.Redis, limit: int = 25) -> list[dict]:
    raw_events = await redis_client.lrange(RECENT_EVENTS_KEY, 0, limit - 1)
    events: list[dict] = []
    for raw_event in raw_events:
        try:
            events.append(json.loads(raw_event))
        except json.JSONDecodeError:
            events.append({"type": "decode_error", "detail": raw_event, "recorded_at": utc_now_iso()})
    return events


async def build_metrics_snapshot_data(redis_backend: str, redis_client: redis.Redis) -> dict:
    summary_raw = await redis_client.hgetall(SUMMARY_METRICS_KEY)
    summary = {field: int(float(value)) for field, value in summary_raw.items()}
    unique_request_phones = await redis_client.hlen(PHONE_REQUESTS_KEY)
    unique_verify_fail_phones = await redis_client.hlen(PHONE_VERIFY_FAIL_KEY)
    top_requested = await get_top_phone_entries(redis_client, PHONE_REQUESTS_KEY)
    top_verify_failed = await get_top_phone_entries(redis_client, PHONE_VERIFY_FAIL_KEY)
    top_verify_success = await get_top_phone_entries(redis_client, PHONE_VERIFY_SUCCESS_KEY)
    provider_metrics = await get_provider_metrics(redis_client)
    recent_events = await get_recent_events(redis_client)

    return {
        "generated_at": utc_now_iso(),
        "service": {
            "provider": OTP_PROVIDER,
            "dev_mode": DEV_OTP_MODE,
            "redis_backend": redis_backend,
            "admin_dashboard_enabled": ADMIN_DASHBOARD_ENABLED,
            "admin_dashboard_auth_configured": ADMIN_DASHBOARD_AUTH_CONFIGURED,
            "otp_ttl_seconds": OTP_TTL_SECONDS,
            "cooldown_seconds": REQUEST_OTP_COOLDOWN_SECONDS,
            "verify_max_attempts": VERIFY_OTP_MAX_ATTEMPTS,
        },
        "summary": {
            "request_total": summary.get("request_total", 0),
            "request_completed_total": summary.get("request_completed_total", 0),
            "request_failed_total": summary.get("request_failed_total", 0),
            "request_blocked_total": summary.get("request_blocked_total", 0),
            "request_blocked_cooldown_total": summary.get("request_blocked_cooldown_total", 0),
            "verify_total": summary.get("verify_total", 0),
            "verify_success_total": summary.get("verify_success_total", 0),
            "verify_failed_total": summary.get("verify_failed_total", 0),
            "verify_failed_invalid_otp_total": summary.get("verify_failed_invalid_otp_total", 0),
            "verify_failed_expired_total": summary.get("verify_failed_expired_total", 0),
            "verify_failed_locked_total": summary.get("verify_failed_locked_total", 0),
            "verify_failed_provider_total": summary.get("verify_failed_provider_total", 0),
            "rate_limit_blocked_total": summary.get("rate_limit_blocked_total", 0),
            "unique_request_phones": unique_request_phones,
            "unique_verify_fail_phones": unique_verify_fail_phones,
        },
        "phones": {
            "top_requests": top_requested,
            "top_verify_failures": top_verify_failed,
            "top_verify_successes": top_verify_success,
        },
        "providers": provider_metrics,
        "recent_events": recent_events,
    }


# --- Translations ---
BACKEND_TRANSLATIONS = {
    "en": {
        "otp_message": "Your OTP code is: {otp_code}. It is valid for {minutes} minutes.",
        "otp_sent": "OTP has been sent to {phone}",
        "otp_verified": "OTP verified successfully.",
        "otp_invalid": "Invalid OTP code. {remaining} attempt(s) remaining.",
        "otp_expired": "OTP not found or has expired. Please request a new one.",
        "otp_locked": "Too many invalid OTP attempts. Please request a new OTP.",
        "cooldown": "OTP was already requested recently. Please wait {seconds} seconds and try again.",
        "ref_expired": "Reference code not found or has expired. Please request a new OTP.",
        "ref_invalid": "Invalid reference code.",
        "phone_invalid": "Invalid phone number. Use local format like 0971234567 or international format.",
    },
    "th": {
        "otp_message": "รหัส OTP ของคุณคือ: {otp_code} รหัสนี้ใช้งานได้ภายใน {minutes} นาที",
        "otp_sent": "ส่ง OTP ไปยัง {phone} แล้ว",
        "otp_verified": "ยืนยัน OTP สำเร็จแล้ว",
        "otp_invalid": "รหัส OTP ไม่ถูกต้อง เหลือความพยายามอีก {remaining} ครั้ง",
        "otp_expired": "ไม่พบ OTP หรือหมดอายุแล้ว กรุณาขอใหม่",
        "otp_locked": "มีการกรอกรหัส OTP ไม่ถูกต้องมากเกินไป กรุณาขอ OTP ใหม่",
        "cooldown": "มีการขอ OTP ไปแล้วเมื่อไม่นานนี้ กรุณารออีก {seconds} วินาทีแล้วลองใหม่",
        "ref_expired": "ไม่พบรหัสอ้างอิงหรือหมดอายุแล้ว กรุณาขอ OTP ใหม่",
        "ref_invalid": "รหัสอ้างอิงไม่ถูกต้อง",
        "phone_invalid": "หมายเลขโทรศัพท์ไม่ถูกต้อง ใช้รูปแบบท้องถิ่นเช่น 0971234567 หรือรูปแบบสากล",
    },
    "kh": {
        "otp_message": "លេខកូដ OTP របស់អ្នកគឺ៖ {otp_code}។ វាមានសុពលភាព {minutes} នាទី",
        "otp_sent": "បានផ្ញើ OTP ទៅ {phone} ហើយ",
        "otp_verified": "បានផ្ទៀងផ្ទាត់ OTP ដោយជោគជ័យ",
        "otp_invalid": "កូដ OTP មិនត្រឹមត្រូវ។ នៅសល់ {remaining} ដងទៀត",
        "otp_expired": "មិនឃើញ OTP ឬវាផុតកំណត់ហើយ សូមស្នើថ្មី",
        "otp_locked": "មានការបញ្ចូល OTP មិនត្រឹមត្រូវច្រើនពេក សូមស្នើ OTP ថ្មី",
        "cooldown": "បានស្នើ OTP រួចហើយថ្មីៗនេះ សូមរង់ចាំ {seconds} វិនាទីហើយសាកល្បងម្តងទៀត",
        "ref_expired": "មិនឃើញលេខយោង ឬវាផុតកំណត់ហើយ សូមស្នើ OTP ថ្មី",
        "ref_invalid": "លេខយោងមិនត្រឹមត្រូវ",
        "phone_invalid": "លេខទូរស័ព្ទមិនត្រឹមត្រូវ សូមប្រើទម្រង់ក្នុងស្រុកដូចជា 0971234567 ឬទម្រង់អន្តរជាតិ",
    },
}

def get_translation(lang: str, key: str, **kwargs) -> str:
    lang = lang.lower() if lang else "th"
    if lang not in BACKEND_TRANSLATIONS:
        lang = "th"
    text = BACKEND_TRANSLATIONS[lang].get(key, BACKEND_TRANSLATIONS["th"].get(key, key))
    return text.format(**kwargs)


async def create_otp_session(phone_number: str, redis_client: redis.Redis, *, include_ref_code: bool, lang: str = "th") -> dict:
    provider_name = OTP_PROVIDER
    response_payload: dict[str, object] = {"phone_number": phone_number, "expires_in": OTP_TTL_SECONDS}
    ref_code = generate_ref_code() if include_ref_code else None

    await record_request_received(redis_client, phone_number)

    cooldown_ttl = await get_remaining_cooldown(redis_client, phone_number)
    if cooldown_ttl > 0:
        detail = get_translation(lang, "cooldown", seconds=cooldown_ttl)
        await record_request_blocked(redis_client, phone_number, "cooldown", detail)
        raise HTTPException(status_code=429, detail=detail)

    if OTP_PROVIDER == "plivo_verify" and not DEV_OTP_MODE:
        try:
            session_uuid = await execute_provider_operation(
                redis_client,
                provider_name,
                "send",
                phone_number,
                lambda: create_plivo_verify_session(phone_number),
            )
        except HTTPException as exc:
            await record_request_failed(redis_client, phone_number, provider_name, parse_http_error_detail(exc))
            raise

        async with redis_client.pipeline(transaction=True) as pipeline:
            await pipeline.set(get_otp_session_key(phone_number), session_uuid, ex=OTP_TTL_SECONDS)
            await pipeline.delete(get_otp_attempts_key(phone_number))
            await pipeline.set(get_otp_cooldown_key(phone_number), "1", ex=REQUEST_OTP_COOLDOWN_SECONDS)
            if ref_code:
                await pipeline.set(get_otp_ref_code_key(phone_number), ref_code, ex=OTP_TTL_SECONDS)
            await pipeline.execute()

        await record_request_completed(
            redis_client,
            phone_number,
            provider_name,
            "success",
            f"OTP session created via {provider_name}.",
        )

        response_payload.update(
            {
                "provider_name": provider_name,
                "send_status": "success",
                "message": get_translation(lang, "otp_sent", phone=phone_number),
            }
        )
        if ref_code:
            response_payload["ref_code"] = ref_code
        return response_payload

    otp_code = generate_otp()
    minutes = OTP_TTL_SECONDS // 60
    sms_lang = "en"
    message = get_translation(sms_lang, "otp_message", otp_code=otp_code, minutes=minutes)

    try:
        if OTP_PROVIDER == "aws_sns" and not DEV_OTP_MODE:
            send_status = await execute_provider_operation(
                redis_client,
                provider_name,
                "send",
                phone_number,
                lambda: send_aws_sns_sms(phone_number, message),
            )
        elif OTP_PROVIDER == "infobip" and not DEV_OTP_MODE:
            send_status = await execute_provider_operation(
                redis_client,
                provider_name,
                "send",
                phone_number,
                lambda: send_infobip_sms(phone_number, message),
            )
        elif OTP_PROVIDER == "plasgate" and not DEV_OTP_MODE:
            send_status = await execute_provider_operation(
                redis_client,
                provider_name,
                "send",
                phone_number,
                lambda: send_plasgate_sms(phone_number, message),
            )
        else:
            provider_name = "dev" if DEV_OTP_MODE else "twilio"
            send_status = await execute_provider_operation(
                redis_client,
                provider_name,
                "send",
                phone_number,
                lambda: send_sms(phone_number, message),
            )
    except HTTPException as exc:
        await record_request_failed(redis_client, phone_number, provider_name, parse_http_error_detail(exc))
        raise

    await store_otp(redis_client, phone_number, otp_code)
    await set_request_cooldown(redis_client, phone_number)
    if ref_code:
        await store_ref_code(redis_client, phone_number, ref_code)

    await record_request_completed(
        redis_client,
        phone_number,
        provider_name,
        "simulated" if send_status == "simulated" else "success",
        f"OTP dispatched via {provider_name}.",
    )

    if send_status == "simulated":
        if DEV_OTP_MODE:
            response_message = f"Development mode: OTP is {otp_code}"
        else:
            response_message = "SMS credentials are not set. OTP was printed in the server console only."
    else:
        response_message = get_translation(lang, "otp_sent", phone=phone_number)

    response_payload.update(
        {
            "provider_name": provider_name,
            "send_status": send_status,
            "message": response_message,
        }
    )
    if ref_code:
        response_payload["ref_code"] = ref_code
    return response_payload


async def verify_otp_session(
    phone_number: str,
    provided_otp: str,
    redis_client: redis.Redis,
    *,
    expected_ref_code: str | None = None,
    lang: str = "th"
) -> str:
    provider_name = OTP_PROVIDER

    await record_verify_attempt(redis_client)

    if expected_ref_code is not None:
        stored_ref_code = await redis_client.get(get_otp_ref_code_key(phone_number))
        if not stored_ref_code:
            detail = get_translation(lang, "ref_expired")
            await record_verify_failure(redis_client, phone_number, "expired", detail)
            raise HTTPException(status_code=400, detail=detail)
        if not secrets.compare_digest(stored_ref_code, expected_ref_code):
            detail = get_translation(lang, "ref_invalid")
            await record_verify_failure(redis_client, phone_number, "invalid_ref_code", detail)
            raise HTTPException(status_code=400, detail=detail)

    if OTP_PROVIDER == "plivo_verify" and not DEV_OTP_MODE:
        session_key = get_otp_session_key(phone_number)
        session_uuid = await redis_client.get(session_key)

        if not session_uuid:
            detail = get_translation(lang, "otp_expired")
            await record_verify_failure(redis_client, phone_number, "expired", detail)
            raise HTTPException(status_code=400, detail=detail)

        try:
            provider_message = await execute_provider_operation(
                redis_client,
                provider_name,
                "verify",
                phone_number,
                lambda: validate_plivo_verify_session(session_uuid, provided_otp),
            )
        except HTTPException as exc:
            await record_verify_provider_failure(redis_client, phone_number, provider_name, parse_http_error_detail(exc))
            raise
        await clear_otp_state(redis_client, phone_number)
        await record_verify_success(redis_client, phone_number, provider_message)
        return provider_message

    redis_key = get_otp_key(phone_number)
    stored_otp = await redis_client.get(redis_key)

    if not stored_otp:
        detail = get_translation(lang, "otp_expired")
        await record_verify_failure(redis_client, phone_number, "expired", detail)
        raise HTTPException(status_code=400, detail=detail)

    if not secrets.compare_digest(stored_otp, provided_otp):
        current_attempts = await record_failed_attempt(redis_client, phone_number)
        remaining_attempts = max(VERIFY_OTP_MAX_ATTEMPTS - current_attempts, 0)

        if current_attempts >= VERIFY_OTP_MAX_ATTEMPTS:
            await clear_otp_state(redis_client, phone_number)
            detail = get_translation(lang, "otp_locked")
            await record_verify_failure(redis_client, phone_number, "locked", detail)
            raise HTTPException(status_code=429, detail=detail)

        detail = get_translation(lang, "otp_invalid", remaining=remaining_attempts)
        await record_verify_failure(redis_client, phone_number, "invalid_otp", detail)
        raise HTTPException(status_code=400, detail=detail)

    await clear_otp_state(redis_client, phone_number)
    success_message = get_translation(lang, "otp_verified")
    await record_verify_success(redis_client, phone_number, success_message)
    return success_message


# --- API Endpoints ---
@app.get("/", include_in_schema=False)
async def root_redirect():
    return RedirectResponse(url="/ops.html", status_code=307)


@app.get("/index.html", include_in_schema=False)
async def index_redirect():
    return RedirectResponse(url="/ops.html", status_code=307)


@app.get("/welcome.html", include_in_schema=False)
async def welcome_redirect():
    return RedirectResponse(url="/ops.html", status_code=307)


@app.get("/login.html", include_in_schema=False)
async def login_redirect():
    return RedirectResponse(url="/ops.html", status_code=307)


@app.get("/verify-phone.html", include_in_schema=False)
async def verify_phone_redirect():
    return RedirectResponse(url="/ops.html#verify-phone", status_code=307)


@app.get("/customers.html", include_in_schema=False)
async def customers_redirect():
    return RedirectResponse(url="/ops.html#customers", status_code=307)


@app.post("/admin/login", response_model=AdminLoginResponse)
@limiter.limit(ADMIN_LOGIN_RATE_LIMIT)
async def admin_login(request: Request, login_request: AdminLoginRequest, redis_client: redis.Redis = Depends(get_redis)):
    if not ADMIN_DASHBOARD_ENABLED:
        raise HTTPException(status_code=404, detail="OTP admin monitor is disabled.")

    if not ADMIN_DASHBOARD_AUTH_CONFIGURED:
        raise HTTPException(status_code=503, detail="OTP admin monitor is enabled but credentials are not configured.")

    username = login_request.username.strip()
    password = login_request.password
    try:
        identity = await authenticate_admin_credentials(redis_client, username, password)
    except (redis.ConnectionError, redis.TimeoutError, asyncio.TimeoutError, OSError) as exc:
        raise HTTPException(status_code=503, detail="Admin storage is temporarily unavailable. Please try again.") from exc

    if not identity:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    role = str(identity.get("role"))
    response = JSONResponse(
        {
            "message": "Login successful.",
            "next_path": resolve_admin_next_path(login_request.next_path, role),
            "role": role,
        }
    )
    response.set_cookie(
        key=ADMIN_SESSION_COOKIE_NAME,
        value=await create_admin_session(redis_client, identity),
        max_age=ADMIN_SESSION_DURATION_SECONDS,
        httponly=True,
        samesite="lax",
        secure=ADMIN_SESSION_COOKIE_SECURE,
        path="/",
    )
    return response


@app.post("/admin/logout", response_model=SuccessResponse)
async def admin_logout(request: Request, redis_client: redis.Redis = Depends(get_redis)):
    session_id = request.cookies.get(ADMIN_SESSION_COOKIE_NAME)
    if session_id:
        session_identity = await load_admin_session(redis_client, session_id)
        await redis_client.delete(admin_session_key(session_id))
        if session_identity:
            await remove_admin_session_from_index(redis_client, str(session_identity.get("username", "")), session_id)
    response = JSONResponse({"message": "Logged out successfully."})
    response.delete_cookie(key=ADMIN_SESSION_COOKIE_NAME, path="/")
    return response


@app.get("/admin/session", response_model=AdminSessionResponse)
async def admin_session_status(request: Request, redis_client: redis.Redis = Depends(get_redis)):
    identity = await get_admin_identity(request, redis_client)
    permissions = dict(identity.get("permissions", {})) if identity else {}
    return {
        "authenticated": identity is not None,
        "username": identity.get("username") if identity else None,
        "role": identity.get("role") if identity else None,
        "permissions": permissions,
        "admin_dashboard_enabled": ADMIN_DASHBOARD_ENABLED,
        "admin_dashboard_auth_configured": ADMIN_DASHBOARD_AUTH_CONFIGURED,
    }


@app.get("/admin/customers", response_model=CustomerRecordsResponse)
async def admin_customers_list(request: Request, redis_client: redis.Redis = Depends(get_redis)):
    await require_admin_request(request, redis_client)
    return {"customers": await load_customer_records(redis_client)}


@app.put("/admin/customers", response_model=CustomerRecordsResponse)
async def admin_customers_save(request: Request, payload: CustomerRecordsPayload, redis_client: redis.Redis = Depends(get_redis)):
    await require_admin_request(request, redis_client)
    customers = await save_customer_records(redis_client, payload.customers)
    try:
        await sync_backup_artifacts(redis_client, request.app.state.redis_backend, customers=customers)
    except Exception as exc:
        safe_console_print(f"[backup] {trim_text(exc)}")
        if GOOGLE_SHEETS_BACKUP_ENABLED and GOOGLE_SHEETS_BACKUP_STRICT:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"customers": customers}


@app.get("/admin/users", response_model=AdminUsersResponse)
async def admin_users_list(request: Request, redis_client: redis.Redis = Depends(get_redis)):
    await require_admin_role(request, redis_client, {ADMIN_ROLE_SUPER_ADMIN})
    users = await load_admin_users(redis_client)
    return {"users": [admin_user_summary(user) for user in users]}


@app.post("/admin/users", response_model=AdminCreateUserResponse)
async def admin_users_create(
    request: Request,
    payload: AdminCreateUserRequest,
    redis_client: redis.Redis = Depends(get_redis),
):
    await require_admin_role(request, redis_client, {ADMIN_ROLE_SUPER_ADMIN})

    username = payload.username.strip()
    password = payload.password
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")
    normalized_username = username.lower()
    if normalized_username in {"admin", "superadmin", ADMIN_DASHBOARD_USERNAME.lower()}:
        raise HTTPException(status_code=400, detail="Username is reserved.")

    users = await load_admin_users(redis_client)
    if any(str(user.get("username", "")).lower() == normalized_username and bool(user.get("active", True)) for user in users):
        raise HTTPException(status_code=409, detail="A user with this username already exists.")

    now = utc_now_iso()
    created_user = {
        "username": username,
        "role": ADMIN_ROLE_STAFF,
        "origin": "manual",
        "password_hash": hash_admin_password(password),
        "created_at": now,
        "updated_at": now,
        "active": True,
    }
    users.append(created_user)
    await save_admin_users(redis_client, users)
    return {
        "message": "Staff user created successfully.",
        "user": admin_user_summary(created_user),
    }


@app.patch("/admin/users/{username}/password", response_model=AdminUpdateUserPasswordResponse)
async def admin_users_update_password(
    username: str,
    request: Request,
    payload: AdminUpdateUserPasswordRequest,
    redis_client: redis.Redis = Depends(get_redis),
):
    await require_admin_role(request, redis_client, {ADMIN_ROLE_SUPER_ADMIN})

    normalized_username = username.strip().lower()
    if not normalized_username:
        raise HTTPException(status_code=400, detail="Username is required.")

    users = await load_admin_users(redis_client)
    target_index = next(
        (
            index
            for index, user in enumerate(users)
            if str(user.get("username", "")).lower() == normalized_username and bool(user.get("active", True))
        ),
        -1,
    )
    if target_index < 0:
        raise HTTPException(status_code=404, detail="User not found.")

    target_user = users[target_index]
    if str(target_user.get("role")) != ADMIN_ROLE_STAFF:
        raise HTTPException(status_code=403, detail="Only staff users can be managed here.")

    now = utc_now_iso()
    target_user["password_hash"] = hash_admin_password(payload.password)
    target_user["updated_at"] = now
    users[target_index] = target_user
    await save_admin_users(redis_client, users)
    await revoke_admin_sessions(redis_client, str(target_user.get("username", "")))
    return {
        "message": "Staff password updated successfully.",
        "user": admin_user_summary(target_user),
    }


@app.delete("/admin/users/{username}", response_model=SuccessResponse)
async def admin_users_delete(
    username: str,
    request: Request,
    redis_client: redis.Redis = Depends(get_redis),
):
    await require_admin_role(request, redis_client, {ADMIN_ROLE_SUPER_ADMIN})

    normalized_username = username.strip().lower()
    if not normalized_username:
        raise HTTPException(status_code=400, detail="Username is required.")

    users = await load_admin_users(redis_client)
    target_user = next(
        (
            user
            for user in users
            if str(user.get("username", "")).lower() == normalized_username and bool(user.get("active", True))
        ),
        None,
    )
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found.")

    if str(target_user.get("role")) != ADMIN_ROLE_STAFF:
        raise HTTPException(status_code=403, detail="Only staff users can be deleted here.")

    remaining_users = [
        user
        for user in users
        if str(user.get("username", "")).lower() != normalized_username
    ]
    await save_admin_users(redis_client, remaining_users)
    await revoke_admin_sessions(redis_client, str(target_user.get("username", "")))
    return {"message": "Staff user deleted successfully."}


@app.get("/health", response_model=HealthResponse)
async def health(request: Request, redis_client: redis.Redis = Depends(get_redis)):
    redis_status = "ok"
    try:
        await redis_client.ping()
    except (redis.ConnectionError, redis.TimeoutError, asyncio.TimeoutError, OSError) as exc:
        redis_status = "degraded"
        safe_console_print(f"[health] redis unavailable: {trim_text(exc)}")
    return {
        "status": "ok",
        "app_version": APP_VERSION,
        "provider": OTP_PROVIDER,
        "dev_mode": DEV_OTP_MODE,
        "redis_backend": request.app.state.redis_backend,
        "redis_status": redis_status,
        "admin_dashboard_enabled": ADMIN_DASHBOARD_ENABLED,
        "admin_dashboard_auth_configured": ADMIN_DASHBOARD_AUTH_CONFIGURED,
    }


@app.get("/admin/metrics")
async def admin_metrics(request: Request, redis_client: redis.Redis = Depends(get_redis)):
    await redis_client.ping()
    await require_admin_role(request, redis_client, {ADMIN_ROLE_SUPER_ADMIN})
    return await build_metrics_snapshot_data(request.app.state.redis_backend, redis_client)


@app.get("/api/v1/status", response_model=ApiStatusResponse)
@limiter.limit(EXTERNAL_API_RATE_LIMIT)
async def api_v1_status(request: Request, redis_client: redis.Redis = Depends(get_redis)):
    await require_external_api_key(request)
    redis_status = "ok"
    try:
        await redis_client.ping()
    except (redis.ConnectionError, redis.TimeoutError, asyncio.TimeoutError, OSError):
        redis_status = "degraded"
    return {
        "status": "ok",
        "api_version": "v1",
        "app_version": APP_VERSION,
        "provider": OTP_PROVIDER,
        "dev_mode": DEV_OTP_MODE,
        "external_api_enabled": True,
        "redis_backend": request.app.state.redis_backend,
        "redis_status": redis_status,
    }


@app.get("/api/v1/customers", response_model=ApiCustomersListResponse)
@limiter.limit(EXTERNAL_API_RATE_LIMIT)
async def api_v1_customers_list(request: Request, redis_client: redis.Redis = Depends(get_redis)):
    await require_external_api_key(request)
    return {"customers": await load_customer_records(redis_client)}


@app.get("/api/v1/customers/{customer_id}", response_model=ApiCustomerRecordResponse)
@limiter.limit(EXTERNAL_API_RATE_LIMIT)
async def api_v1_customer_get(customer_id: str, request: Request, redis_client: redis.Redis = Depends(get_redis)):
    await require_external_api_key(request)
    target_id = customer_id.strip().lower()
    if not target_id:
        raise HTTPException(status_code=400, detail="Customer ID is required.")

    customers = await load_customer_records(redis_client)
    customer = next((record for record in customers if str(record.get("id", "")).strip().lower() == target_id), None)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found.")

    return {"customer": CustomerRecord.model_validate(customer)}


@app.post("/api/v1/customers", response_model=ApiCustomerRecordResponse)
@limiter.limit(EXTERNAL_API_RATE_LIMIT)
async def api_v1_customer_create(
    request: Request,
    payload: ApiCustomerUpsertRequest,
    redis_client: redis.Redis = Depends(get_redis),
):
    await require_external_api_key(request)
    customer = normalize_api_customer_request(payload)
    saved_customers = await upsert_customer_record(redis_client, payload)
    try:
        await sync_backup_artifacts(redis_client, request.app.state.redis_backend, customers=saved_customers)
    except Exception as exc:
        safe_console_print(f"[backup] {trim_text(exc)}")
    return {"customer": customer}


@app.put("/api/v1/customers/{customer_id}", response_model=ApiCustomerRecordResponse)
@limiter.limit(EXTERNAL_API_RATE_LIMIT)
async def api_v1_customer_update(
    customer_id: str,
    request: Request,
    payload: ApiCustomerUpsertRequest,
    redis_client: redis.Redis = Depends(get_redis),
):
    await require_external_api_key(request)
    if customer_id.strip().lower() != payload.id.strip().lower():
        raise HTTPException(status_code=400, detail="Customer ID in the path must match the request body.")
    customer = normalize_api_customer_request(payload)
    saved_customers = await upsert_customer_record(redis_client, payload)
    try:
        await sync_backup_artifacts(redis_client, request.app.state.redis_backend, customers=saved_customers)
    except Exception as exc:
        safe_console_print(f"[backup] {trim_text(exc)}")
    return {"customer": customer}


@app.delete("/api/v1/customers/{customer_id}", response_model=SuccessResponse)
@limiter.limit(EXTERNAL_API_RATE_LIMIT)
async def api_v1_customer_delete(
    customer_id: str,
    request: Request,
    redis_client: redis.Redis = Depends(get_redis),
):
    await require_external_api_key(request)
    target_id = customer_id.strip().lower()
    if not target_id:
        raise HTTPException(status_code=400, detail="Customer ID is required.")

    customers = await load_customer_records(redis_client)
    remaining_customers = [
        record
        for record in customers
        if str(record.get("id", "")).strip().lower() != target_id
    ]
    if len(remaining_customers) == len(customers):
        raise HTTPException(status_code=404, detail="Customer not found.")

    saved_customers = await save_customer_records(redis_client, [CustomerRecord.model_validate(record) for record in remaining_customers])
    try:
        await sync_backup_artifacts(redis_client, request.app.state.redis_backend, customers=saved_customers)
    except Exception as exc:
        safe_console_print(f"[backup] {trim_text(exc)}")
    return {"message": "Customer deleted successfully."}


@app.post("/api/v1/otp/request", response_model=StaffAssistedRequestResponse)
@limiter.limit(EXTERNAL_API_RATE_LIMIT)
async def api_v1_request_otp(
    request: Request,
    otp_request: ApiOtpRequest,
    redis_client: redis.Redis = Depends(get_redis),
):
    await require_external_api_key(request)
    phone_number = normalize_phone_number(otp_request.phone)
    session_payload = await create_otp_session(phone_number, redis_client, include_ref_code=False, lang=otp_request.lang)
    return {
        "status": "success",
        "expires_in": int(session_payload["expires_in"]),
    }


@app.post("/api/v1/otp/verify", response_model=StaffAssistedVerifyResponse)
@limiter.limit(EXTERNAL_API_RATE_LIMIT)
async def api_v1_verify_otp(
    request: Request,
    otp_verify: ApiOtpVerify,
    redis_client: redis.Redis = Depends(get_redis),
):
    await require_external_api_key(request)
    phone_number = normalize_phone_number(otp_verify.phone)
    provided_otp = validate_otp_format(otp_verify.otp)
    message = await verify_otp_session(phone_number, provided_otp, redis_client, lang=otp_verify.lang)
    return {"status": "success", "message": message}


@app.post("/api/request-otp", response_model=StaffAssistedRequestResponse)
@limiter.limit(REQUEST_OTP_RATE_LIMIT)
async def staff_request_otp(
    request: Request,
    otp_request: StaffAssistedOTPRequest,
    redis_client: redis.Redis = Depends(get_redis),
):
    phone_number = normalize_phone_number(otp_request.phone)
    session_payload = await create_otp_session(phone_number, redis_client, include_ref_code=False, lang=otp_request.lang)
    return {
        "status": "success",
        "expires_in": int(session_payload["expires_in"]),
    }


@app.post("/api/verify-otp", response_model=StaffAssistedVerifyResponse)
@limiter.limit(VERIFY_OTP_RATE_LIMIT)
async def staff_verify_otp(
    request: Request,
    otp_verify: StaffAssistedOTPVerify,
    redis_client: redis.Redis = Depends(get_redis),
):
    phone_number = normalize_phone_number(otp_verify.phone)
    provided_otp = validate_otp_format(otp_verify.otp)
    message = await verify_otp_session(phone_number, provided_otp, redis_client, lang=otp_verify.lang)
    return {"status": "success", "message": message}


@app.post("/request-otp", response_model=SuccessResponse)
@limiter.limit(REQUEST_OTP_RATE_LIMIT)
async def request_otp(
    request: Request,
    otp_request: OTPRequest,
    redis_client: redis.Redis = Depends(get_redis),
):
    phone_number = normalize_phone_number(otp_request.phone)
    session_payload = await create_otp_session(phone_number, redis_client, include_ref_code=False, lang=otp_request.lang)
    return {"message": str(session_payload["message"])}


@app.post("/verify-otp", response_model=SuccessResponse)
@limiter.limit(VERIFY_OTP_RATE_LIMIT)
async def verify_otp(
    request: Request,
    otp_verify: OTPVerify,
    redis_client: redis.Redis = Depends(get_redis),
):
    phone_number = normalize_phone_number(otp_verify.phone)
    provided_otp = validate_otp_format(otp_verify.otp)
    message = await verify_otp_session(phone_number, provided_otp, redis_client, lang=otp_verify.lang)
    return {"message": message}


# --- Mount Static Files ---
app.mount("/", StaticFiles(directory="static", html=True), name="static")

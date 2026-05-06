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
ADMIN_SESSION_COOKIE_NAME = os.getenv("ADMIN_SESSION_COOKIE_NAME", "otp_admin_session").strip() or "otp_admin_session"
ADMIN_SESSION_DURATION_SECONDS = validate_positive_int("ADMIN_SESSION_DURATION_SECONDS", 28800)
ADMIN_SESSION_COOKIE_SECURE = env_flag("ADMIN_SESSION_COOKIE_SECURE", not DEV_OTP_MODE)
ADMIN_SESSION_SECRET = (
    os.getenv("ADMIN_SESSION_SECRET", "").strip()
    or f"{ADMIN_DASHBOARD_USERNAME}:{ADMIN_DASHBOARD_PASSWORD}:otp-admin-session"
)
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
GOOGLE_SHEETS_SERVICE_ACCOUNT_JSON = os.getenv("GOOGLE_SHEETS_SERVICE_ACCOUNT_JSON", "").strip()
GOOGLE_SHEETS_SERVICE_ACCOUNT_FILE = os.getenv("GOOGLE_SHEETS_SERVICE_ACCOUNT_FILE", "").strip()
GOOGLE_SHEETS_BACKUP_TIMEOUT_SECONDS = validate_positive_int("GOOGLE_SHEETS_BACKUP_TIMEOUT_SECONDS", 15)
GOOGLE_SHEETS_SCOPE = "https://www.googleapis.com/auth/spreadsheets"

if OTP_LENGTH != 6:
    raise RuntimeError("OTP_LENGTH must be 6 to match the current client validation.")


# --- Metrics Keys ---
SUMMARY_METRICS_KEY = "otp_metrics:summary"
PHONE_REQUESTS_KEY = "otp_metrics:phone:requests"
PHONE_VERIFY_FAIL_KEY = "otp_metrics:phone:verify_fail"
PHONE_VERIFY_SUCCESS_KEY = "otp_metrics:phone:verify_success"
RECENT_EVENTS_KEY = "otp_metrics:events"
PROVIDER_METRICS_PREFIX = "otp_metrics:provider:"
DATA_DIR = Path(__file__).resolve().parent / "data"
CUSTOMERS_FILE = DATA_DIR / "customers.json"


# --- Rate Limiter Setup ---
limiter = Limiter(key_func=get_remote_address, default_limits=["10/minute"])


async def close_redis_client(redis_client: redis.Redis) -> None:
    close_method = getattr(redis_client, "aclose", None) or getattr(redis_client, "close", None)
    if close_method is not None:
        result = close_method()
        if asyncio.iscoroutine(result):
            await result


# --- Redis Connection Lifespan ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    if USE_FAKE_REDIS:
        redis_client = fakeredis.FakeAsyncRedis(decode_responses=True)
        redis_backend = "fakeredis"
    else:
        if not REDIS_URL:
            raise RuntimeError("REDIS_URL is required when USE_FAKE_REDIS is false.")
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        await redis_client.ping()
        redis_backend = "redis"

    app.state.redis = redis_client
    app.state.redis_backend = redis_backend

    if GOOGLE_SHEETS_BACKUP_ENABLED and GOOGLE_SHEETS_BACKUP_STRICT and not is_google_sheets_backup_ready():
        raise RuntimeError(
            "Google Sheets backup is enabled in strict mode but configuration or dependencies are missing."
        )

    print(
        "--- OTP CONFIG --- "
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

    try:
        yield
    finally:
        await close_redis_client(redis_client)


# --- FastAPI App Initialization ---
app = FastAPI(
    title="OTP Service API",
    description="A simple API to request and verify One-Time Passwords (OTPs).",
    version="1.2.0",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


@app.middleware("http")
async def disable_cache(request: Request, call_next):
    if ADMIN_DASHBOARD_ENABLED and is_protected_admin_path(request.url.path):
        if not ADMIN_DASHBOARD_AUTH_CONFIGURED:
            return build_admin_unavailable_response()
        if not is_admin_authenticated(request):
            return build_admin_auth_response()

    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    redis_client = getattr(request.app.state, "redis", None)
    if redis_client is not None and request.url.path in {"/request-otp", "/verify-otp", "/api/request-otp", "/api/verify-otp"}:
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


class StaffAssistedOTPVerify(BaseModel):
    phone: str = Field(..., description="Customer phone number in local format.", examples=["0812345678"])
    otp: str = Field(..., description="The 6-digit OTP received by the customer.", examples=["123456"])


class AdminLoginRequest(BaseModel):
    username: str = Field(..., min_length=1, examples=["Admin"])
    password: str = Field(..., min_length=1, examples=["icash123"])
    next_path: str = Field(default="/ops.html", examples=["/ops.html"])


class SuccessResponse(BaseModel):
    message: str


class AdminLoginResponse(BaseModel):
    message: str
    next_path: str


class AdminSessionResponse(BaseModel):
    authenticated: bool
    admin_dashboard_enabled: bool
    admin_dashboard_auth_configured: bool


class StaffAssistedRequestResponse(BaseModel):
    status: str
    expires_in: int


class StaffAssistedVerifyResponse(BaseModel):
    status: str
    message: str


class HealthResponse(BaseModel):
    status: str
    provider: str
    dev_mode: bool
    redis_backend: str
    admin_dashboard_enabled: bool
    admin_dashboard_auth_configured: bool


class CustomerRecord(BaseModel):
    id: str = Field(..., min_length=1, examples=["CUS-001"])
    name: str = Field(..., min_length=1, examples=["Sokha Chan"])
    phone_number: str = Field(..., min_length=1, examples=["0971234567"])
    otp: str = Field(default="", examples=["123456"])


class CustomerRecordsPayload(BaseModel):
    customers: list[CustomerRecord]


class CustomerRecordsResponse(BaseModel):
    customers: list[CustomerRecord]


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


def is_valid_admin_auth_header(auth_header: str) -> bool:
    if not auth_header or not auth_header.startswith("Basic "):
        return False

    try:
        encoded = auth_header.split(" ", 1)[1].strip()
        decoded = base64.b64decode(encoded).decode("utf-8")
        username, password = decoded.split(":", 1)
    except Exception:
        return False

    return secrets.compare_digest(username, ADMIN_DASHBOARD_USERNAME) and secrets.compare_digest(
        password,
        ADMIN_DASHBOARD_PASSWORD,
    )


def create_admin_session_token(username: str) -> str:
    expires_at = int(time.time()) + ADMIN_SESSION_DURATION_SECONDS
    payload = f"{username}|{expires_at}"
    signature = hmac.new(
        ADMIN_SESSION_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    token = f"{payload}|{signature}"
    return base64.urlsafe_b64encode(token.encode("utf-8")).decode("ascii")


def validate_admin_session_token(token: str | None) -> bool:
    if not token or not ADMIN_DASHBOARD_AUTH_CONFIGURED:
        return False

    try:
        decoded = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        username, expires_at_raw, provided_signature = decoded.rsplit("|", 2)
        payload = f"{username}|{expires_at_raw}"
        expected_signature = hmac.new(
            ADMIN_SESSION_SECRET.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        expires_at = int(expires_at_raw)
    except Exception:
        return False

    if not secrets.compare_digest(username, ADMIN_DASHBOARD_USERNAME):
        return False
    if not hmac.compare_digest(provided_signature, expected_signature):
        return False
    return expires_at >= int(time.time())


def is_admin_authenticated(request: Request) -> bool:
    if not ADMIN_DASHBOARD_AUTH_CONFIGURED:
        return False
    if validate_admin_session_token(request.cookies.get(ADMIN_SESSION_COOKIE_NAME)):
        return True
    return is_valid_admin_auth_header(request.headers.get("Authorization", ""))


def require_admin_request(request: Request) -> None:
    if not ADMIN_DASHBOARD_ENABLED:
        raise HTTPException(status_code=404, detail="OTP admin monitor is disabled.")
    if not ADMIN_DASHBOARD_AUTH_CONFIGURED:
        raise HTTPException(status_code=503, detail="OTP admin monitor is enabled but credentials are not configured.")
    if not is_admin_authenticated(request):
        raise HTTPException(status_code=401, detail="Authentication required for the OTP admin monitor.")


def normalize_customer_record(record: CustomerRecord) -> dict[str, str]:
    return {
        "id": record.id.strip(),
        "name": record.name.strip(),
        "phone_number": record.phone_number.strip(),
        "otp": record.otp.strip(),
    }


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


def build_google_sheet_payload(records: list[dict[str, str]]) -> list[list[str]]:
    rows = [["ID", "Name", "PhoneNumber", "OTP"]]
    for record in records:
        rows.append(
            [
                record.get("id", ""),
                record.get("name", ""),
                record.get("phone_number", ""),
                record.get("otp", ""),
            ]
        )
    return rows


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

    token = await asyncio.to_thread(get_google_sheets_access_token)
    clear_range = build_google_sheet_range(GOOGLE_SHEETS_BACKUP_SHEET_NAME, "A:D")
    update_rows = build_google_sheet_payload(records)
    update_range = build_google_sheet_range(
        GOOGLE_SHEETS_BACKUP_SHEET_NAME,
        f"A1:D{max(len(update_rows), 1)}",
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    timeout = httpx.Timeout(GOOGLE_SHEETS_BACKUP_TIMEOUT_SECONDS)

    async with httpx.AsyncClient(timeout=timeout) as client:
        clear_response = await client.post(
            "https://sheets.googleapis.com/v4/spreadsheets/"
            f"{GOOGLE_SHEETS_BACKUP_SPREADSHEET_ID}/values/{quote(clear_range, safe='')}:clear",
            headers=headers,
        )
        if clear_response.is_error:
            raise RuntimeError(
                f"Unable to clear Google Sheet backup range: {extract_http_error_detail(clear_response)}"
            )

        update_response = await client.put(
            "https://sheets.googleapis.com/v4/spreadsheets/"
            f"{GOOGLE_SHEETS_BACKUP_SPREADSHEET_ID}/values/{quote(update_range, safe='')}",
            headers=headers,
            params={"valueInputOption": "RAW"},
            json={
                "majorDimension": "ROWS",
                "values": update_rows,
            },
        )
        if update_response.is_error:
            raise RuntimeError(
                f"Unable to update Google Sheet backup: {extract_http_error_detail(update_response)}"
            )


def load_customer_records() -> list[dict[str, str]]:
    if not CUSTOMERS_FILE.exists():
        return []

    try:
        raw_records = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
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


def save_customer_records(records: list[CustomerRecord]) -> list[dict[str, str]]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    normalized_records = [normalize_customer_record(record) for record in records]
    CUSTOMERS_FILE.write_text(
        json.dumps(normalized_records, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return normalized_records


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


async def build_metrics_snapshot(request: Request, redis_client: redis.Redis) -> dict:
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
            "redis_backend": request.app.state.redis_backend,
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
        "phone_invalid": "Invalid phone number. Use local format like 0971234567 or international format."
    },
    "th": {
        "otp_message": "รหัส OTP ของคุณคือ: {otp_code} (ใช้งานได้นาน {minutes} นาที)",
        "otp_sent": "ส่งรหัส OTP ไปยัง {phone} สำเร็จ",
        "otp_verified": "ยืนยันรหัส OTP สำเร็จ",
        "otp_invalid": "รหัส OTP ไม่ถูกต้อง เหลือโอกาสอีก {remaining} ครั้ง",
        "otp_expired": "ไม่พบรหัส OTP หรือรหัสหมดอายุแล้ว กรุณาขอรหัสใหม่",
        "otp_locked": "กรอกรหัสผิดเกินจำนวนครั้งที่กำหนด กรุณาขอรหัส OTP ใหม่",
        "cooldown": "คุณเพิ่งขอรหัส OTP ไปเมื่อครู่ กรุณารอ {seconds} วินาทีแล้วลองใหม่",
        "ref_expired": "รหัสอ้างอิงไม่ถูกต้องหรือหมดอายุแล้ว กรุณาขอ OTP ใหม่",
        "ref_invalid": "รหัสอ้างอิงไม่ถูกต้อง",
        "phone_invalid": "เบอร์โทรศัพท์ไม่ถูกต้อง กรุณาใช้รูปแบบ 0971234567 หรือแบบสากល"
    },
    "kh": {
        "otp_message": "កូដ OTP របស់អ្នកគឺ: {otp_code}។ មានសុពលភាពរយៈពេល {minutes} នាទី។",
        "otp_sent": "កូដ OTP ត្រូវបានផ្ញើទៅកាន់ {phone}",
        "otp_verified": "ការផ្ទៀងផ្ទាត់កូដ OTP បានជោគជ័យ។",
        "otp_invalid": "កូដ OTP មិនត្រឹមត្រូវ។ នៅសល់ការសាកល្បង {remaining} ដងទៀត។",
        "otp_expired": "រកមិនឃើញកូដ OTP ឬកូដបានហួសសុពលភាព។ សូមស្នើសុំកូដថ្មី។",
        "otp_locked": "ការសាកល្បងកូដខុសច្រើនដងពេក។ សូមស្នើសុំកូដ OTP ថ្មី។",
        "cooldown": "អ្នកបានស្នើសុំកូដ OTP រួចហើយ។ សូមរង់ចាំ {seconds} វិនាទី រួចព្យាយាមម្តងទៀត។",
        "ref_expired": "រកមិនឃើញកូដយោង ឬបានហួសសុពលភាព។ សូមស្នើសុំកូដ OTP ថ្មី។",
        "ref_invalid": "កូដយោងមិនត្រឹមត្រូវ។",
        "phone_invalid": "លេខទូរស័ព្ទមិនត្រឹមត្រូវ។ សូមប្រើទម្រង់ដូចជា 0971234567 ឬទម្រង់អន្តរជាតិ។"
    }
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
                "message": f"OTP has been sent to {phone_number} via Plivo Verify.",
            }
        )
        if ref_code:
            response_payload["ref_code"] = ref_code
        return response_payload

    otp_code = generate_otp()
    minutes = OTP_TTL_SECONDS // 60
    sms_lang = "en" if OTP_PROVIDER == "plasgate" else lang
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
async def admin_login(login_request: AdminLoginRequest):
    if not ADMIN_DASHBOARD_ENABLED:
        raise HTTPException(status_code=404, detail="OTP admin monitor is disabled.")

    if not ADMIN_DASHBOARD_AUTH_CONFIGURED:
        raise HTTPException(status_code=503, detail="OTP admin monitor is enabled but credentials are not configured.")

    username = login_request.username.strip()
    password = login_request.password
    next_path = login_request.next_path if is_safe_next_path(login_request.next_path) else "/ops.html"

    if not (
        secrets.compare_digest(username, ADMIN_DASHBOARD_USERNAME)
        and secrets.compare_digest(password, ADMIN_DASHBOARD_PASSWORD)
    ):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    response = JSONResponse({"message": "Login successful.", "next_path": next_path})
    response.set_cookie(
        key=ADMIN_SESSION_COOKIE_NAME,
        value=create_admin_session_token(username),
        max_age=ADMIN_SESSION_DURATION_SECONDS,
        httponly=True,
        samesite="lax",
        secure=ADMIN_SESSION_COOKIE_SECURE,
        path="/",
    )
    return response


@app.post("/admin/logout", response_model=SuccessResponse)
async def admin_logout():
    response = JSONResponse({"message": "Logged out successfully."})
    response.delete_cookie(key=ADMIN_SESSION_COOKIE_NAME, path="/")
    return response


@app.get("/admin/session", response_model=AdminSessionResponse)
async def admin_session_status(request: Request):
    return {
        "authenticated": is_admin_authenticated(request),
        "admin_dashboard_enabled": ADMIN_DASHBOARD_ENABLED,
        "admin_dashboard_auth_configured": ADMIN_DASHBOARD_AUTH_CONFIGURED,
    }


@app.get("/admin/customers", response_model=CustomerRecordsResponse)
async def admin_customers_list(request: Request):
    require_admin_request(request)
    return {"customers": load_customer_records()}


@app.put("/admin/customers", response_model=CustomerRecordsResponse)
async def admin_customers_save(request: Request, payload: CustomerRecordsPayload):
    require_admin_request(request)
    customers = save_customer_records(payload.customers)
    try:
        await sync_customer_records_to_google_sheets(customers)
    except Exception as exc:
        safe_console_print(f"[google-sheets-backup] {trim_text(exc)}")
        if GOOGLE_SHEETS_BACKUP_ENABLED and GOOGLE_SHEETS_BACKUP_STRICT:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"customers": customers}


@app.get("/health", response_model=HealthResponse)
async def health(request: Request, redis_client: redis.Redis = Depends(get_redis)):
    await redis_client.ping()
    return {
        "status": "ok",
        "provider": OTP_PROVIDER,
        "dev_mode": DEV_OTP_MODE,
        "redis_backend": request.app.state.redis_backend,
        "admin_dashboard_enabled": ADMIN_DASHBOARD_ENABLED,
        "admin_dashboard_auth_configured": ADMIN_DASHBOARD_AUTH_CONFIGURED,
    }


@app.get("/admin/metrics")
async def admin_metrics(request: Request, redis_client: redis.Redis = Depends(get_redis)):
    await redis_client.ping()
    return await build_metrics_snapshot(request, redis_client)


@app.post("/api/request-otp", response_model=StaffAssistedRequestResponse)
@limiter.limit(REQUEST_OTP_RATE_LIMIT)
async def staff_request_otp(
    request: Request,
    otp_request: StaffAssistedOTPRequest,
    redis_client: redis.Redis = Depends(get_redis),
):
    phone_number = normalize_phone_number(otp_request.phone)
    session_payload = await create_otp_session(phone_number, redis_client, include_ref_code=False)
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
    message = await verify_otp_session(phone_number, provided_otp, redis_client)
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

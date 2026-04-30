import os
import random
import re
import redis.asyncio as redis
import fakeredis
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
except ImportError:
    pass

# --- Configuration ---
# You can use environment variables for Redis configuration in a real-world scenario
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
OTP_TTL_SECONDS = 300  # 5 minutes
DEFAULT_COUNTRY_CODE = os.getenv("DEFAULT_COUNTRY_CODE", "855").lstrip("+")
DEV_OTP_MODE = os.getenv("DEV_OTP_MODE", "false").strip().lower() in {"1", "true", "yes", "on"}
OTP_PROVIDER = os.getenv("OTP_PROVIDER", "dev").strip().lower()
REQUEST_OTP_RATE_LIMIT = "30/minute" if DEV_OTP_MODE else "1/minute"

# --- Rate Limiter Setup ---
# The limiter will use the client's IP address to track requests.
limiter = Limiter(key_func=get_remote_address, default_limits=["10/minute"])

# --- Redis Connection Lifespan ---
# Use a lifespan manager to handle the Redis connection pool
# This ensures the connection is established on startup and closed on shutdown.
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Connect to Redis using fakeredis
    app.state.redis = fakeredis.FakeAsyncRedis(decode_responses=True)
    print(
        "--- OTP CONFIG --- "
        f"provider={OTP_PROVIDER}, "
        f"dev_mode={DEV_OTP_MODE}, "
        f"infobip_key_present={'yes' if bool(os.getenv('INFOBIP_API_KEY')) else 'no'}, "
        f"twilio_sid_present={'yes' if bool(os.getenv('TWILIO_ACCOUNT_SID')) else 'no'}"
    )
    yield
    # Close connection
    await app.state.redis.close()

# --- FastAPI App Initialization ---
app = FastAPI(
    title="OTP Service API",
    description="A simple API to request and verify One-Time Passwords (OTPs).",
    version="1.0.0",
    lifespan=lifespan
)
# Add the rate-limiting middleware to the application
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


@app.middleware("http")
async def disable_cache(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many OTP requests. Please wait a moment and try again."},
    )


app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

# --- Pydantic Models for Request/Response ---
class OTPRequest(BaseModel):
    phone: str = Field(..., description="The user's phone number.", example="1234567890")

class OTPVerify(BaseModel):
    phone: str = Field(..., description="The user's phone number.", example="1234567890")
    otp: str = Field(..., description="The 6-digit OTP received by the user.", example="123456")

class SuccessResponse(BaseModel):
    message: str

# --- Helper Functions ---
async def get_redis(request: Request) -> redis.Redis:
    """Dependency to get the Redis connection from application state."""
    return request.app.state.redis

def generate_otp() -> str:
    """Generates a random 6-digit OTP."""
    return "".join([str(random.randint(0, 9)) for _ in range(6)])

def normalize_phone_number(phone: str) -> str:
    """Normalizes local phone numbers into E.164 format for SMS providers."""
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
            detail=f"Invalid phone number. Use local format like 0971234567 or E.164 format like +{DEFAULT_COUNTRY_CODE}971234567.",
        )

    return cleaned

async def send_sms(phone: str, message: str) -> str:
    """
    Sends an SMS using Twilio.
    Reads credentials from environment variables.
    Falls back to console printing if credentials are not set.
    """
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    twilio_phone = os.getenv("TWILIO_PHONE_NUMBER")

    if DEV_OTP_MODE:
        print("--- DEVELOPMENT MODE: OTP SMS IS PRINTED HERE ONLY ---")
        print(f"To: {phone}")
        print(f"Message: {message}")
        print("------------------------------------")
        return "simulated"

    if not all([account_sid, auth_token, twilio_phone]):
        print("--- TWILIO CREDENTIALS NOT FOUND ---")
        print("--- DEVELOPMENT MODE: OTP SMS IS PRINTED HERE ONLY ---")
        print(f"To: {phone}")
        print(f"Message: {message}")
        print("------------------------------------")
        return "simulated"

    try:
        from twilio.rest import Client
        from twilio.base.exceptions import TwilioRestException

        client = Client(account_sid, auth_token)
        twilio_message = client.messages.create(
            body=message,
            from_=twilio_phone,
            to=phone
        )
        print(f"--- SMS sent successfully to {phone} (SID: {twilio_message.sid}) ---")
        return "sent"
    except TwilioRestException as e:
        print(f"--- FAILED TO SEND SMS ---")
        print(f"Twilio Error {e.code}: {e.msg}")
        raise HTTPException(status_code=502, detail=f"Twilio Error {e.code}: {e.msg}")
    except Exception as e:
        print(f"--- FAILED TO SEND SMS ---")
        print(f"Error: {e}")
        # Re-raise as an HTTPException to inform the client
        raise HTTPException(status_code=500, detail="Failed to send OTP SMS.")


async def send_aws_sns_sms(phone: str, message: str) -> str:
    """
    Sends an SMS using AWS SNS.
    Relies on standard AWS credentials/configuration resolution.
    """
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError

        region_name = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
        client = boto3.client("sns", region_name=region_name)
        response = client.publish(
            PhoneNumber=phone,
            Message=message,
            MessageAttributes={
                "AWS.SNS.SMS.SMSType": {
                    "DataType": "String",
                    "StringValue": "Transactional",
                }
            },
        )
        message_id = response.get("MessageId")
        print(f"--- AWS SNS SMS accepted for {phone} (MessageId: {message_id}) ---")
        return "sent"
    except (BotoCoreError, ClientError) as e:
        error_message = str(e)
        print("--- FAILED TO SEND AWS SNS SMS ---")
        print(f"Error: {error_message}")
        raise HTTPException(status_code=502, detail=f"AWS SNS error: {error_message}")


async def send_infobip_sms(phone: str, message: str) -> str:
    """
    Sends an SMS using the Infobip SMS API.
    """
    api_key = os.getenv("INFOBIP_API_KEY")
    base_url = os.getenv("INFOBIP_BASE_URL", "https://api.infobip.com").strip().rstrip("/")
    sender = os.getenv("INFOBIP_SENDER", "ServiceSMS").strip()

    if not api_key:
        raise HTTPException(status_code=500, detail="Infobip is selected but INFOBIP_API_KEY is missing.")

    try:
        import requests

        response = requests.post(
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
            timeout=30,
        )

        if response.status_code >= 400:
            error_body = response.text.strip()
            print("--- FAILED TO SEND INFOBIP SMS ---")
            print(f"Status: {response.status_code}")
            print(f"Body: {error_body}")
            raise HTTPException(status_code=502, detail=f"Infobip error {response.status_code}: {error_body}")

        payload = response.json()
        message_id = None
        messages = payload.get("messages") or []
        if messages:
            message_id = messages[0].get("messageId")
        print(f"--- INFOBIP SMS accepted for {phone} (MessageId: {message_id}) ---")
        return "sent"
    except HTTPException:
        raise
    except Exception as e:
        error_message = str(e)
        print("--- FAILED TO SEND INFOBIP SMS ---")
        print(f"Error: {error_message}")
        raise HTTPException(status_code=502, detail=f"Infobip error: {error_message}")


async def create_plivo_verify_session(phone: str):
    """
    Sends an OTP using Plivo Verify and returns the provider session UUID.
    """
    auth_id = os.getenv("PLIVO_AUTH_ID")
    auth_token = os.getenv("PLIVO_AUTH_TOKEN")
    verify_app_uuid = os.getenv("PLIVO_VERIFY_APP_UUID")

    if not all([auth_id, auth_token, verify_app_uuid]):
        raise HTTPException(
            status_code=500,
            detail="Plivo is selected but PLIVO_AUTH_ID, PLIVO_AUTH_TOKEN, or PLIVO_VERIFY_APP_UUID is missing.",
        )

    try:
        import plivo

        client = plivo.RestClient(auth_id, auth_token)
        response = client.verify_session.create(
            recipient=phone,
            app_uuid=verify_app_uuid,
            channel="sms",
        )
        session_uuid = getattr(response, "session_uuid", None)
        if not session_uuid:
            raise HTTPException(status_code=502, detail="Plivo Verify did not return a session UUID.")
        return session_uuid
    except HTTPException:
        raise
    except Exception as e:
        error_message = str(e)
        print("--- FAILED TO CREATE PLIVO VERIFY SESSION ---")
        print(f"Error: {error_message}")
        raise HTTPException(status_code=502, detail=f"Plivo Verify error: {error_message}")


async def validate_plivo_verify_session(session_uuid: str, otp: str):
    """
    Validates an OTP using a Plivo Verify session UUID.
    """
    auth_id = os.getenv("PLIVO_AUTH_ID")
    auth_token = os.getenv("PLIVO_AUTH_TOKEN")

    if not all([auth_id, auth_token]):
        raise HTTPException(
            status_code=500,
            detail="Plivo validation is selected but PLIVO_AUTH_ID or PLIVO_AUTH_TOKEN is missing.",
        )

    try:
        import plivo

        client = plivo.RestClient(auth_id, auth_token)
        response = client.verify_session.validate(session_uuid=session_uuid, otp=otp)
        return getattr(response, "message", "OTP verified successfully.")
    except HTTPException:
        raise
    except Exception as e:
        error_message = str(e)
        print("--- FAILED TO VALIDATE PLIVO VERIFY SESSION ---")
        print(f"Error: {error_message}")
        raise HTTPException(status_code=400, detail=f"Plivo Verify validation failed: {error_message}")

# --- API Endpoints ---
@app.post("/request-otp", response_model=SuccessResponse)
@limiter.limit(REQUEST_OTP_RATE_LIMIT)
async def request_otp(request: Request, otp_request: OTPRequest, redis_client: redis.Redis = Depends(get_redis)):
    """
    Generates a 6-digit OTP, stores it in Redis, and sends it via SMS.
    """
    phone_number = normalize_phone_number(otp_request.phone)

    if OTP_PROVIDER == "plivo_verify" and not DEV_OTP_MODE:
        session_uuid = await create_plivo_verify_session(phone_number)
        await redis_client.set(f"otp_session:{phone_number}", session_uuid, ex=OTP_TTL_SECONDS)
        return {"message": f"OTP has been sent to {phone_number} via Plivo Verify."}

    otp_code = generate_otp()

    # Send the OTP via SMS
    try:
        if OTP_PROVIDER == "aws_sns" and not DEV_OTP_MODE:
            send_status = await send_aws_sns_sms(
                phone_number,
                f"Your OTP code is: {otp_code}. It is valid for 5 minutes.",
            )
        elif OTP_PROVIDER == "infobip" and not DEV_OTP_MODE:
            send_status = await send_infobip_sms(
                phone_number,
                f"Your OTP code is: {otp_code}. It is valid for 5 minutes.",
            )
        else:
            send_status = await send_sms(phone_number, f"Your OTP code is: {otp_code}. It is valid for 5 minutes.")
    except HTTPException as e:
        # If send_sms raised an error, propagate it to the client
        raise e

    if send_status == "simulated":
        await redis_client.set(f"otp:{phone_number}", otp_code, ex=OTP_TTL_SECONDS)
        if DEV_OTP_MODE:
            return {"message": f"Development mode: OTP is {otp_code}"}
        return {"message": "Twilio credentials are not set. OTP was printed in the server console only."}

    # Store the OTP only after the SMS provider accepts the message.
    await redis_client.set(f"otp:{phone_number}", otp_code, ex=OTP_TTL_SECONDS)

    return {"message": f"OTP has been sent to {phone_number}"}


@app.post("/verify-otp", response_model=SuccessResponse)
async def verify_otp(otp_verify: OTPVerify, redis_client: redis.Redis = Depends(get_redis)):
    """
    Verifies the user-provided OTP against the one stored in Redis.
    """
    phone_number = normalize_phone_number(otp_verify.phone)
    provided_otp = otp_verify.otp.strip()

    if OTP_PROVIDER == "plivo_verify" and not DEV_OTP_MODE:
        session_key = f"otp_session:{phone_number}"
        session_uuid = await redis_client.get(session_key)

        if not session_uuid:
            raise HTTPException(status_code=400, detail="OTP session not found or has expired. Please request a new one.")

        provider_message = await validate_plivo_verify_session(session_uuid, provided_otp)
        await redis_client.delete(session_key)
        return {"message": provider_message}

    redis_key = f"otp:{phone_number}"

    # Retrieve the stored OTP from Redis
    stored_otp = await redis_client.get(redis_key)

    if not stored_otp:
        # This means the OTP has expired or never existed
        raise HTTPException(status_code=400, detail="OTP not found or has expired. Please request a new one.")

    if stored_otp != provided_otp:
        # The provided OTP does not match the stored one
        raise HTTPException(status_code=400, detail="Invalid OTP code.")

    # OTP is correct, so we delete it from Redis to prevent reuse
    await redis_client.delete(redis_key)

    return {"message": "OTP verified successfully."}

# --- Mount Static Files ---
# This will serve files from the 'static' directory
app.mount("/", StaticFiles(directory="static", html=True), name="static")

# --- To run this application ---
# 1. Make sure you have Redis running.
# 2. Install dependencies: pip install -r requirements.txt
# 3. Run the server: uvicorn main:app --reload
#
# Example using curl:
#
# Request OTP:
# curl -X POST "http://127.0.0.1:8000/request-otp" -H "Content-Type: application/json" -d '{"phone": "5551234567"}'
#
# Verify OTP (replace 123456 with the actual OTP from console):
# curl -X POST "http://127.0.0.1:8000/verify-otp" -H "Content-Type: application/json" -d '{"phone": "5551234567", "otp": "123456"}'

# OTP Service API

This document describes the versioned external API for system-to-system integration.

## Overview

- Base path: `/api/v1`
- Authentication: API key in a request header
- Default header name: `X-API-Key`
- API key source: `EXTERNAL_API_KEYS`
- Rate limit: controlled by `EXTERNAL_API_RATE_LIMIT`

The external API is separate from the admin console login/session flow.

## Versioning

- API version: `v1`
- App version: returned by `GET /health` and `GET /api/v1/status`
- The current app build version is stored in [`VERSION`](/D:/OTP_project/VERSION)

## Authentication

Send one valid key from `EXTERNAL_API_KEYS` in the header named by `EXTERNAL_API_HEADER_NAME`.

Example:

```http
X-API-Key: your-secret-key
```

If the header is missing or invalid, the API returns `401`.

## Common Response Codes

- `200` successful read or update
- `201` created by the API
- `400` invalid request data
- `401` missing or invalid API key
- `403` not allowed
- `404` record not found
- `429` rate limit exceeded
- `503` service temporarily unavailable or API not configured

## Status

### `GET /api/v1/status`

Returns a lightweight status payload for integration checks.

Example:

```bash
curl -H "X-API-Key: your-secret-key" \
  https://your-domain.example.com/api/v1/status
```

Response:

```json
{
  "status": "ok",
  "api_version": "v1",
  "app_version": "v0.0.2",
  "provider": "plasgate",
  "dev_mode": false,
  "external_api_enabled": true,
  "redis_backend": "redis",
  "redis_status": "ok"
}
```

## OTP

### `POST /api/v1/otp/request`

Request an OTP for a phone number.

Request body:

```json
{
  "phone": "0812345678",
  "lang": "en"
}
```

Fields:

- `phone` required
- `lang` optional, defaults to `en`

Response:

```json
{
  "status": "success",
  "expires_in": 300
}
```

### `POST /api/v1/otp/verify`

Verify an OTP for a phone number.

Request body:

```json
{
  "phone": "0812345678",
  "otp": "123456",
  "lang": "en"
}
```

Response:

```json
{
  "status": "success",
  "message": "OTP verified successfully."
}
```

## Customers

Customer records are stored in Redis and are also backed up by the existing backup flow.

### `GET /api/v1/customers`

List all customer records.

Response:

```json
{
  "customers": [
    {
      "id": "CUS-001",
      "name": "Sokha Chan",
      "phone_number": "0971234567",
      "otp": "123456",
      "timestamp": "2026-05-06T09:18:47Z"
    }
  ]
}
```

### `GET /api/v1/customers/{customer_id}`

Fetch one customer by ID.

Example:

```bash
curl -H "X-API-Key: your-secret-key" \
  https://your-domain.example.com/api/v1/customers/CUS-001
```

Response:

```json
{
  "customer": {
    "id": "CUS-001",
    "name": "Sokha Chan",
    "phone_number": "0971234567",
    "otp": "123456",
    "timestamp": "2026-05-06T09:18:47Z"
  }
}
```

### `POST /api/v1/customers`

Create or update a customer record by `id`.

Request body:

```json
{
  "id": "CUS-001",
  "name": "Sokha Chan",
  "phone_number": "0971234567",
  "otp": "123456",
  "timestamp": "2026-05-06T09:18:47Z"
}
```

Behavior:

- If the `id` already exists, the record is replaced.
- If the `id` does not exist, the record is inserted at the top of the list.
- If `timestamp` is blank, the server fills it automatically.

Response:

```json
{
  "customer": {
    "id": "CUS-001",
    "name": "Sokha Chan",
    "phone_number": "0971234567",
    "otp": "123456",
    "timestamp": "2026-05-06T09:18:47Z"
  }
}
```

### `PUT /api/v1/customers/{customer_id}`

Update an existing customer record.

Rules:

- The `{customer_id}` in the path must match the `id` in the body.
- If the IDs do not match, the API returns `400`.

### `DELETE /api/v1/customers/{customer_id}`

Delete a customer record by ID.

Response:

```json
{
  "message": "Customer deleted successfully."
}
```

## Example Integration Flow

1. Call `POST /api/v1/otp/request` with a phone number.
2. Ask the user for the OTP they received.
3. Call `POST /api/v1/otp/verify` with the same phone number and OTP.
4. Save or update the customer with `POST /api/v1/customers`.
5. Use `GET /api/v1/customers` or `GET /api/v1/status` for syncing and monitoring.

## Environment Variables

Required:

- `EXTERNAL_API_KEYS`

Optional:

- `EXTERNAL_API_HEADER_NAME` defaults to `X-API-Key`
- `EXTERNAL_API_RATE_LIMIT` defaults to `60/minute`

Example:

```env
EXTERNAL_API_KEYS=key-one,key-two
EXTERNAL_API_HEADER_NAME=X-API-Key
EXTERNAL_API_RATE_LIMIT=60/minute
```

## Notes

- Keep API keys outside the repository.
- Use a separate key for each environment if possible.
- Rotate keys if they are ever exposed.
- The external API is intended for internal integrations and trusted systems.

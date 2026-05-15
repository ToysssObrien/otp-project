# คู่มือเชื่อม OTP แบบย่อสำหรับ Dev

เอกสารนี้สรุปเฉพาะสิ่งที่ต้องใช้เพื่อเชื่อมระบบหลังบ้านของคุณกับ OTP Service ของเรา

## สิ่งที่ต้องรู้

- Base URL: `/api/v1`
- Auth: ส่ง `X-API-Key`
- API key มาจาก `EXTERNAL_API_KEYS`
- ถ้าไม่มี key หรือ key ไม่ถูกต้อง จะได้ `401`

## Flow ที่แนะนำ

1. ระบบของคุณเรียก `POST /api/v1/otp/request`
2. ผู้ใช้กรอก OTP ในระบบของคุณ
3. ระบบของคุณเรียก `POST /api/v1/otp/verify`
4. ถ้าผ่าน ให้ระบบของคุณบันทึกสถานะต่อ

## Endpoint ที่ใช้จริง

- `GET /api/v1/status`
- `POST /api/v1/otp/request`
- `POST /api/v1/otp/verify`
- `GET /api/v1/customers`
- `GET /api/v1/customers/{customer_id}`
- `POST /api/v1/customers`
- `PUT /api/v1/customers/{customer_id}`
- `DELETE /api/v1/customers/{customer_id}`

## ตัวอย่าง request

```http
POST /api/v1/otp/request
X-API-Key: your-secret-key
Content-Type: application/json

{
  "phone": "0812345678",
  "lang": "en"
}
```

```http
POST /api/v1/otp/verify
X-API-Key: your-secret-key
Content-Type: application/json

{
  "phone": "0812345678",
  "otp": "123456",
  "lang": "en"
}
```

## Customer API แบบสั้น

ใช้ `POST /api/v1/customers` ถ้าต้องการสร้างหรืออัปเดตข้อมูลลูกค้า

ตัวอย่าง:

```json
{
  "id": "CUS-001",
  "name": "Sokha Chan",
  "phone_number": "0971234567",
  "otp": "123456",
  "timestamp": "2026-05-06T09:18:47Z"
}
```

ถ้า `id` ซ้ำ ระบบจะอัปเดตข้อมูลเดิมให้

## Response ที่ควรเตรียมรองรับ

- `200` สำเร็จ
- `400` request ไม่ถูกต้อง
- `401` API key ผิดหรือไม่ได้ส่ง
- `404` ไม่พบข้อมูล
- `429` เรียกถี่เกิน
- `503` ระบบไม่พร้อมใช้งาน

## Environment ที่ต้องตั้ง

```env
EXTERNAL_API_KEYS=key-one,key-two
EXTERNAL_API_HEADER_NAME=X-API-Key
EXTERNAL_API_RATE_LIMIT=60/minute
```

## หมายเหตุสำหรับ dev

- เรียกจาก backend ของระบบคุณ ไม่ควรเรียกตรงจาก browser
- เก็บ key ใน secret/env เท่านั้น
- ถ้าจะใช้งานจริง ให้เรียก `GET /api/v1/status` ตรวจระบบก่อน

ถ้าต้องการรายละเอียด request/response ครบ ๆ ดูต่อที่ [API.md](/D:/OTP_project/API.md)

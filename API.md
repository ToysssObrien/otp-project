# เอกสาร API ของ OTP Service

เอกสารฉบับนี้อธิบาย API แบบมีเวอร์ชันสำหรับการเชื่อมต่อกับระบบอื่นในอนาคต

## ภาพรวม

- Base path: `/api/v1`
- การยืนยันตัวตน: ใช้ API key ผ่าน request header
- ชื่อ header เริ่มต้น: `X-API-Key`
- แหล่งที่มาของ API key: `EXTERNAL_API_KEYS`
- การจำกัดจำนวนครั้ง: ควบคุมด้วย `EXTERNAL_API_RATE_LIMIT`

API ชุดนี้แยกจาก flow ล็อกอินของ admin console โดยสิ้นเชิง

## เวอร์ชัน

- API version: `v1`
- App version: ส่งกลับจาก `GET /health` และ `GET /api/v1/status`
- เวอร์ชันของแอปปัจจุบันเก็บไว้ที่ไฟล์ [`VERSION`](/D:/OTP_project/VERSION)

## การยืนยันตัวตน

ส่ง API key ที่ถูกต้องอย่างน้อย 1 ค่า จาก `EXTERNAL_API_KEYS` ใน header ที่กำหนดโดย `EXTERNAL_API_HEADER_NAME`

ตัวอย่าง:

```http
X-API-Key: your-secret-key
```

ถ้าไม่ส่ง header หรือส่ง key ไม่ถูกต้อง ระบบจะตอบ `401`

## รหัสสถานะที่พบบ่อย

- `200` อ่านหรืออัปเดตสำเร็จ
- `201` สร้างรายการสำเร็จ
- `400` ข้อมูล request ไม่ถูกต้อง
- `401` ไม่มี API key หรือ API key ไม่ถูกต้อง
- `403` ไม่มีสิทธิ์
- `404` ไม่พบข้อมูล
- `429` เกิน rate limit
- `503` ระบบไม่พร้อมใช้งานชั่วคราว หรือยังไม่ได้เปิด API

## Status

### `GET /api/v1/status`

ใช้ตรวจสถานะระบบสำหรับการเชื่อมต่อ

ตัวอย่าง:

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

ใช้ขอ OTP สำหรับเบอร์โทรศัพท์

Request body:

```json
{
  "phone": "0812345678",
  "lang": "en"
}
```

ฟิลด์:

- `phone` จำเป็น
- `lang` ไม่บังคับ ค่าเริ่มต้นคือ `en`

Response:

```json
{
  "status": "success",
  "expires_in": 300
}
```

### `POST /api/v1/otp/verify`

ใช้ยืนยัน OTP สำหรับเบอร์โทรศัพท์

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

ข้อมูลลูกค้าถูกเก็บใน Redis และมีระบบ backup ต่อเนื่องจาก flow ที่มีอยู่แล้ว

### `GET /api/v1/customers`

ใช้ดึงรายการลูกค้าทั้งหมด

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

ใช้ดึงข้อมูลลูกค้าตามรหัสลูกค้า

ตัวอย่าง:

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

ใช้สร้างหรืออัปเดตข้อมูลลูกค้าตาม `id`

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

พฤติกรรม:

- ถ้า `id` มีอยู่แล้ว ระบบจะทับข้อมูลเดิม
- ถ้า `id` ยังไม่มี ระบบจะเพิ่มรายการใหม่ไว้ด้านบนสุด
- ถ้า `timestamp` ว่าง ระบบจะใส่เวลาให้เอง

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

ใช้อัปเดตข้อมูลลูกค้าที่มีอยู่แล้ว

กติกา:

- `{customer_id}` ใน path ต้องตรงกับ `id` ใน body
- ถ้าไม่ตรงกัน ระบบจะตอบ `400`

### `DELETE /api/v1/customers/{customer_id}`

ใช้ลบข้อมูลลูกค้าตามรหัสลูกค้า

Response:

```json
{
  "message": "Customer deleted successfully."
}
```

## ตัวอย่าง flow การใช้งาน

1. เรียก `POST /api/v1/otp/request` ด้วยเบอร์โทรศัพท์
2. ให้ผู้ใช้กรอก OTP ที่ได้รับ
3. เรียก `POST /api/v1/otp/verify` ด้วยเบอร์เดิมและ OTP เดิม
4. บันทึกหรืออัปเดตข้อมูลลูกค้าด้วย `POST /api/v1/customers`
5. ใช้ `GET /api/v1/customers` หรือ `GET /api/v1/status` เพื่อ sync ข้อมูลและตรวจสถานะ

## ตัวแปรสภาพแวดล้อม

จำเป็น:

- `EXTERNAL_API_KEYS`

ตัวเลือกเพิ่มเติม:

- `EXTERNAL_API_HEADER_NAME` ค่าเริ่มต้นคือ `X-API-Key`
- `EXTERNAL_API_RATE_LIMIT` ค่าเริ่มต้นคือ `60/minute`

ตัวอย่าง:

```env
EXTERNAL_API_KEYS=key-one,key-two
EXTERNAL_API_HEADER_NAME=X-API-Key
EXTERNAL_API_RATE_LIMIT=60/minute
```

## หมายเหตุ

- อย่าเก็บ API key ไว้ใน repository
- ถ้าเป็นไปได้ ให้ใช้ key แยกกันตามแต่ละ environment
- ถ้า key หลุด ควรเปลี่ยนทันที
- API ชุดนี้ออกแบบมาสำหรับระบบภายในหรือระบบที่เชื่อถือได้

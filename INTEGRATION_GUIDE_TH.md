# คู่มือเชื่อมระบบ OTP กับระบบภายนอก

เอกสารฉบับนี้ทำขึ้นสำหรับทีม dev ที่จะเชื่อมระบบหลังบ้านของคุณกับ OTP Service โดยตรง

## เป้าหมาย

ใช้ระบบ OTP ของเราแบบ server-to-server โดยไม่ต้องให้ผู้ใช้เข้าเว็บ `otpverify.icashbank.com` เอง

เหมาะกับ flow แบบนี้:

1. ระบบภายนอกรับข้อมูลลูกค้า
2. ระบบภายนอกเรียก API เพื่อขอ OTP
3. ผู้ใช้กรอก OTP กลับในระบบภายนอก
4. ระบบภายนอกเรียก API เพื่อยืนยัน OTP
5. ถ้าผ่าน ให้ระบบภายนอกบันทึกสถานะงานต่อไป

## สิ่งที่ต้องมี

ฝั่งระบบที่จะเชื่อม ต้องส่งค่าต่อไปนี้มาใน request:

- เบอร์โทรศัพท์
- OTP ที่ผู้ใช้ได้รับ
- API key สำหรับเรียกระบบ OTP ของเรา

## การยืนยันตัวตน

API ของเราป้องกันด้วย header

```http
X-API-Key: your-secret-key
```

ค่าที่ใช้ได้ต้องตรงกับ `EXTERNAL_API_KEYS` ที่ตั้งไว้บนเซิร์ฟเวอร์

ถ้าไม่ส่ง key หรือส่งไม่ถูกต้อง จะได้ `401 Unauthorized`

## Base URL

ใช้ path แบบ versioned

```text
/api/v1
```

ตัวอย่าง full URL:

```text
https://your-domain.example.com/api/v1/otp/request
```

## Endpoint ที่ใช้จริง

| Method | Path | ใช้ทำอะไร |
| --- | --- | --- |
| `GET` | `/api/v1/status` | ตรวจสอบว่าระบบพร้อมใช้งาน |
| `POST` | `/api/v1/otp/request` | ขอ OTP |
| `POST` | `/api/v1/otp/verify` | ยืนยัน OTP |
| `GET` | `/api/v1/customers` | ดึงรายชื่อลูกค้าทั้งหมด |
| `GET` | `/api/v1/customers/{customer_id}` | ดึงลูกค้าทีละรายการ |
| `POST` | `/api/v1/customers` | สร้างหรืออัปเดตลูกค้า |
| `PUT` | `/api/v1/customers/{customer_id}` | อัปเดตลูกค้าตาม id |
| `DELETE` | `/api/v1/customers/{customer_id}` | ลบลูกค้า |

## Flow ที่แนะนำ

### 1) ขอ OTP

ส่งเบอร์โทรของผู้ใช้ไปที่

```http
POST /api/v1/otp/request
```

ตัวอย่าง body:

```json
{
  "phone": "0812345678",
  "lang": "en"
}
```

คำตอบที่ได้:

```json
{
  "status": "success",
  "expires_in": 300
}
```

### 2) ให้ผู้ใช้กรอก OTP

ระบบของคุณรับ OTP จากผู้ใช้ตามหน้าจอของคุณเอง

### 3) ยืนยัน OTP

ส่ง OTP ที่ผู้ใช้กรอกไปที่

```http
POST /api/v1/otp/verify
```

ตัวอย่าง body:

```json
{
  "phone": "0812345678",
  "otp": "123456",
  "lang": "en"
}
```

ถ้าผ่าน:

```json
{
  "status": "success",
  "message": "OTP verified successfully."
}
```

### 4) บันทึกผลในระบบของคุณ

หลัง verify ผ่านแล้ว ระบบของคุณค่อย mark สถานะว่า verified หรือส่งต่อไปขั้นตอนถัดไป

## รายละเอียดแต่ละ API

### `GET /api/v1/status`

ใช้เช็กว่า API พร้อมใช้งานหรือไม่

ตัวอย่าง:

```bash
curl -H "X-API-Key: your-secret-key" \
  https://your-domain.example.com/api/v1/status
```

ตัวอย่าง response:

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

### `POST /api/v1/otp/request`

ใช้ขอ OTP ใหม่

Request body:

```json
{
  "phone": "0812345678",
  "lang": "en"
}
```

ฟิลด์:

- `phone` จำเป็น
- `lang` ไม่บังคับ ใช้ `en`, `th`, หรือ `kh`

Response:

```json
{
  "status": "success",
  "expires_in": 300
}
```

### `POST /api/v1/otp/verify`

ใช้ตรวจ OTP ที่ผู้ใช้กรอก

Request body:

```json
{
  "phone": "0812345678",
  "otp": "123456",
  "lang": "en"
}
```

Response เมื่อผ่าน:

```json
{
  "status": "success",
  "message": "OTP verified successfully."
}
```

### `GET /api/v1/customers`

ดึงรายการลูกค้าทั้งหมด

Response:

```json
{
  "customers": []
}
```

### `GET /api/v1/customers/{customer_id}`

ดึงลูกค้าทีละรายการจากรหัสลูกค้า

ตัวอย่าง:

```bash
curl -H "X-API-Key: your-secret-key" \
  https://your-domain.example.com/api/v1/customers/CUS-001
```

### `POST /api/v1/customers`

ใช้สร้างหรืออัปเดตลูกค้าด้วย `id`

ตัวอย่าง body:

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

- ถ้า `id` ซ้ำ ระบบจะอัปเดตข้อมูลเดิม
- ถ้า `id` ใหม่ ระบบจะสร้างรายการใหม่
- ถ้า `timestamp` ว่าง ระบบจะใส่ให้เอง

### `PUT /api/v1/customers/{customer_id}`

ใช้อัปเดตข้อมูลลูกค้าเดิม

เงื่อนไขสำคัญ:

- `customer_id` ใน URL ต้องตรงกับ `id` ใน body
- ถ้าไม่ตรงกัน จะได้ `400`

### `DELETE /api/v1/customers/{customer_id}`

ใช้ลบข้อมูลลูกค้า

Response:

```json
{
  "message": "Customer deleted successfully."
}
```

## รหัสตอบกลับที่ควรรู้

- `200` สำเร็จ
- `400` ข้อมูลที่ส่งมาไม่ถูกต้อง
- `401` API key ไม่ถูกต้องหรือไม่ส่งมา
- `404` ไม่พบข้อมูล
- `429` เรียกถี่เกิน rate limit
- `503` ระบบยังไม่พร้อมใช้งาน

## ตัวอย่างการเรียกจริง

### ขอ OTP

```bash
curl -X POST https://your-domain.example.com/api/v1/otp/request ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: your-secret-key" ^
  -d "{\"phone\":\"0812345678\",\"lang\":\"en\"}"
```

### ยืนยัน OTP

```bash
curl -X POST https://your-domain.example.com/api/v1/otp/verify ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: your-secret-key" ^
  -d "{\"phone\":\"0812345678\",\"otp\":\"123456\",\"lang\":\"en\"}"
```

## ตัวแปรที่ต้องตั้งบนเซิร์ฟเวอร์

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

## ข้อแนะนำสำหรับ dev

- ใช้ API นี้จาก backend ของระบบคุณ ไม่ควรเรียกตรงจาก browser
- เก็บ API key ไว้ใน secret manager หรือ env ของ server เท่านั้น
- ถ้าจะทำ staging และ production ควรแยก key คนละชุด
- ถ้า key หลุด ให้ rotate ทันที
- ถ้าต้องการตรวจว่าระบบพร้อมไหม ให้เรียก `GET /api/v1/status` ก่อน

## สรุปสั้น

ระบบ OTP ของเราเชื่อมกับระบบภายนอกได้จริงผ่าน API ที่มีอยู่แล้ว

สิ่งที่ทีม dev ต้องทำคือ:

1. ขอ OTP ด้วย `POST /api/v1/otp/request`
2. รับ OTP จากผู้ใช้
3. ตรวจ OTP ด้วย `POST /api/v1/otp/verify`
4. ถ้าผ่าน ให้ระบบของคุณไปทำงานต่อ


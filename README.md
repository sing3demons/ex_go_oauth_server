# Go OAuth 2.0 & OIDC Server

โปรเจกต์นี้คือเซิร์ฟเวอร์สำหรับจัดการการยืนยันตัวตน (Authentication) และสิทธิ์การเข้าถึง (Authorization) ที่พัฒนาขึ้นโดยใช้ภาษา Go โดยเน้นสถาปัตยกรรมแบบ Clean Architecture และรองรับมาตรฐานฟีเจอร์ของ **OAuth 2.0 ร่วมกับ OpenID Connect (OIDC)** 

---

## 🛠 Technology Stack
- **Language**: Go 1.22+ (ใช้ Standard Routing `net/http`)
- **Primary Database**: MongoDB (สำหรับเก็บ Users และ Clients)
- **Cache/Session/Transient Store**: Redis (สำหรับเก็บ Authorization Codes และ Token ชั่วคราว)
- **Cryptography**: `crypto/rsa`, `golang-jwt/jwt/v5` สำหรับแจก JWT และทำ JWKS

---

## 📂 โครงสร้างโปรเจกต์ (Project Structure)

โปรเจกต์นี้ยึดรูปแบบ Standard Layout และเน้นแยกส่วนโค้ดเพื่อให้อ่านง่าย:

```text
.
├── cmd/
│   └── server/
│       └── main.go              # จุดเริ่มต้นโปรแกรม (Entry point) ควบคุม Config และ Router
├── internal/
│   ├── config/                  # ดึงและจัดการตัวแปร Environment Variables
│   ├── adapters/                # ตัวเชื่อมต่อไปยังฐานข้อมูลและแคช
│   │   ├── mongo_store/         # ตัวจัดการ Client ของ MongoDB
│   │   └── redis_store/         # ตัวจัดการ Client ของ Redis
│   ├── core/                    # **ส่วนกลาง** Business Logic ของ OIDC และ Model ต่างๆ (รอสร้าง)
│   └── handlers/                # หน้าต่างรับ Request (HTTP Handlers)
│       └── discovery.go         # API สำหรับ Discovery และแจกกุญแจ
├── pkg/
│   └── crypto/                  # เครื่องมือ Helper (เช่นระบบสร้าง RSA Key คู่สำหรับระบบ JWT)
├── docker-compose.yml           # ไฟล์ตั้งค่าสำหรับเปิด Base Infrastructures แบบ Local (Mongo/Redis)
└── go.mod / go.sum
```

---

## 🚀 วิธีการรันโปรเจกต์ (How to run locally)

1. **เปิดตู้คอนเทนเนอร์ฐานข้อมูล (MongoDB & Redis)**
   เราได้เตรียม `docker-compose.yml` เอาไว้ให้แล้ว ให้สั่งคำสั่งนี้ที่ Root path ของโปรเจกต์:
   ```bash
   docker-compose up -d
   ```
   *ตรวจสอบว่า Mongo รันที่พอร์ต `27017` และ Redis รันที่พอร์ต `6379` ครบถ้วน*

2. **ดาวน์โหลด Dependencies ของ Go**
   ```bash
   go mod tidy
   ```

3. **สั่งรันเซิร์ฟเวอร์หลัก (OIDC Server)**
   สามารถรันคำสั่งเริ่มเซิร์ฟเวอร์ (ค่าเริ่มต้นจะอยู่ที่พอร์ต `8080`):
   ```bash
   go run cmd/server/main.go
   ```

---

## 🌐 Endpoints ปัจจุบัน (API อ้างอิง)

| Method | Endpoint | รายละเอียด / หน้าที่ |
| --- | --- | --- |
| `GET` | `/.well-known/openid-configuration` | **OIDC Discovery**: แสดงค่า Metadata และความสามารถที่ Server นี้รองรับ เพื่อให้ระบบอื่น (Client) ทราบว่าเราเป็นใคร |
| `GET` | `/jwks.json` | **JWKS**: ปล่อย Public Keys (รูปแบบ JSON Web Key Set) เอาไว้ให้ Client ตรวจสอบว่า ID Token (JWT) ถูกแจกออกมาจากเซิร์ฟเวอร์นี้จริงๆ โดยไม่ถูกปลอมแปลง |
| `GET` | `/health` | ตรวจสอบสถานะการทำงานของ Web Server เบื้องต้น |

*(หมายเหตุ: ส่วนที่เกี่ยวกับการ Auth พอร์ตหลัก เช่น `/authorize`, `/token` และฐานข้อมูล กำลังอยู่ในช่วงระหว่างการพัฒนาครับ)*

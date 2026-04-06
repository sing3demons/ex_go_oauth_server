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

├── cmd/
│   ├── client/                  # [NEW] แอปทดสอบ Ralying Party (ยิงขอดู OIDC) พอร์ต 3000
│   │   └── main.go              
│   └── server/
│       └── main.go              # จุดเริ่มต้นโปรแกรม OIDC Server พอร์ต 8080
├── internal/
│   ├── config/                  # จัดการตัวแปร Environment Variables
│   ├── adapters/                # เชื่อมต่อ Database และ Redis
│   │   ├── mongo_store/         # User, Client, RefreshToken, RSA Keys
│   │   └── redis_store/         # Cache (AuthCode, Session, Transaction)
│   ├── core/                    # **ส่วนกลาง** Business Logic ของ OIDC และ Model
│   │   ├── models/              
│   │   ├── ports/               
│   │   └── services/            # บริการต่างๆ (OAuthService, KeyService)
│   └── handlers/                # หน้าต่างรับ Request (HTTP Handlers)
│       ├── admin.go             # จัดการระบบขึ้นทะเบียน Client
│       ├── discovery.go         # API สำหรับ Discovery และ JWKS
│       ├── oauth.go             # API คุมการ Login, Token, Consent ฯลฯ
│       └── register.go          # ระบบสมัครสมาชิก
├── pkg/
│   └── crypto/                  # เครื่องมือ Helper (ระบบสร้าง RSA Key)
├── templates/                   # หน้าจอ UI ต่างๆ (Login, Consent, Admin)
├── docker-compose.yml           # ไฟล์ตั้งค่า Docker ประกอบร่าง Mongo/Redis
└── go.mod / go.sum

---

## 🚀 วิธีการรันโปรเจกต์ (How to run locally)

1. **เปิดตู้คอนเทนเนอร์ฐานข้อมูล (MongoDB & Redis)**
   เราได้เตรียม `docker-compose.yml` เอาไว้ให้แล้ว ให้สั่งคำสั่งนี้ที่ Root path ของโปรเจกต์:
   ```bash
   docker-compose up -d
   ```

2. **ดาวน์โหลด Dependencies ของ Go**
   ```bash
   go mod tidy
   ```

3. **สั่งรันเซิร์ฟเวอร์หลัก (OIDC Server)**
   เปิด Terminal ของคุณและสั่งรันขุมพลังหลักที่เตรียมมา:
   ```bash
   go run cmd/server/main.go
   ```
   *ใช้งานได้ที่ `http://localhost:8080/admin/dashboard` (User/Pass: `admin`/`admin_password`)*

4. **ทดสอบกับ Client App ตัวอย่าง**
   เมื่อสร้าง Client จากหน้า Admin Dashboard ของเซิร์ฟเวอร์หลักแล้ว ให้นำ `client_id` และ `client_secret` เข้าไปเปลี่ยนในบรรทัดแรกๆ ของโค้ด `cmd/client/main.go` จากนั้น... เปิด Terminal หน้าต่างที่สองแล้วสั่งรันขนานกันไปเลย:
   ```bash
   go run cmd/client/main.go
   ```
   *ใช้งานฝั่งแอปได้ที่ `http://localhost:3000`*

---

## 🗝️ สถาปัตยกรรม Key Management (JWKS)

ระบบการจัดการกุญแจเข้ารหัส (RSA Key Pair) สำหรับโปรเจกต์นี้ถูกออกแบบเป็น **Graceful Key Rotation แบบ Hybrid (MongoDB + Redis)** ทรงประสิทธิภาพระดับ Enterprise โดยทำงานผ่าน Cache เพื่อรองรับการสเกลแบบ Multiple Instances (Stateless):

1. **Redis Caching (`jwks:current`)**: ทำหน้าที่เป็นหน้าด่านคอยแคชกุญแจตัวปัจจุบัน (Active Key) ทำให้เซิร์ฟเวอร์ดึงไปแจก Access Token (JWT) ได้รวดเร็ว โดยผูก TTL หมดอายุตามค่าตัวแปร `KEY_ROTATION_DURATION` (ค่าตั้งต้น 30 วัน)
2. **MongoDB Fallback & Persistence**: ต้นแบบกุญแจจะถูกฝังประวัติไว้ใน Collection `keys` ถ้าระบบพบว่ากุญแจใน Redis หมดอายุการใช้งานแล้ว เซิร์ฟเวอร์จะสั่งปั่นกุญแจตัวใหม่ (Generate New Key) ส่งเข้าไปเรียงตัวใน MongoDB และดึงกลับไปพักใน Redis คืน ทำให้การผลัดเปลี่ยนกุญแจ (Key Rotation) เกิดขึ้นได้อย่างรวดเร็วและเป็นอัตโนมัติ
3. **Grace Period & Auto-Prune**: 
   - ระบบดูแล Token เก่าๆ อย่างนุ่มนวล โดยเมื่อมีคำขอมาที่ Endpoint `/jwks.json` แทนที่จะตอบแค่กุญแจตัวล่าสุดเพียงตัวเดียว ระบบจะเอาประวัติกุญแจเก่าที่เพิ่งหมดอายุไปไม่เกิน 14 วัน (`KEY_GRACE_PERIOD`) ส่งไปโชว์คู่กันด้วย ช่วยให้ระบบฝั่ง Client ยังคง Verify ค่าเก่าได้ไม่มีกระตุก (Downtime 0%)
   - **Auto-Prune**: ระบบจะควบคุมขยะและข้อมูลบวมใน Database ให้มีประวัติกองอยู่ไม่เกินเพดานสูงสุดตลอดกาล (`KEY_MAX_RETENTION_COUNT` = 5 อัน) กุญแจที่เกินจากโควต้าจะถูกลบกวาดทิ้งให้เองทันทีแบบเนียนๆ

### 📊 แผนภาพจำลองการทำงาน (Flow Diagram)

```mermaid
sequenceDiagram
    participant API as OIDC Service
    participant Redis as Redis (Cache)
    participant Mongo as MongoDB (Storage)

    Note over API: จังหวะต้องการ Sign JWT หรืออ่าน JWKS
    API->>Redis: 1. ควานหากุญแจปัจุบัน (jwks:current)
    alt มีแคช (Cache Hit)
        Redis-->>API: 2. ได้หน้ากุญแจ เอาไปใช้ต่อทันที
    else หมดอายุ (Cache Miss / TTL Expired)
        Redis-->>API: ไม่เจอ (Not Found)
        API->>Mongo: 3. ค้นหาคีย์จากประวัติล่าสุด
        alt ประวัติหมดอายุ หรือ ไม่มีขัอมูล (Expired/Empty)
            API->>API: 4. สร้าง RSA Key คู่ใหม่ (Generate)
            API->>Mongo: 5. Insert ลงบันทึกประวัติ
            API->>Mongo: 6. กวาดลบกุญแจเก่าที่เกินโควต้า 5 ตัวทิ้ง (Auto-Prune)
            API->>Redis: 7. เซฟลงแคชตั้งเวลาพัก (TTL)
        else ยังใช้งานได้แต่แคสหด
            Mongo-->>API: ได้หน้ากุญแจ
            API->>Redis: เซฟลงแคชไว้แบบเดิม
        end
    end
    Note over API: กระบวนการคัดกรองเสร็จสิ้นพร้อมใช้งาน
```

---

## 🌐 Endpoints ปัจจุบัน (API อ้างอิง)

### 📌 Discovery & Metadata
| Method | Endpoint | รายละเอียด |
| :-: | --- | --- |
| `GET` | `/.well-known/openid-configuration` | **OIDC Discovery**: แสดงค่า Metadata และความสามารถที่ Server นี้รองรับ |
| `GET` | `/jwks.json` | **JWKS**: ปล่อย Public Keys สำหรับให้ Client ตรวจสอบลายเซ็น JWT ด้วยตัวเอง |

### 🔐 OAuth & OIDC Core
| Method | Endpoint | รายละเอียด |
| :-: | --- | --- |
| `GET` | `/authorize` | จุดเริ่มต้นของ Authorization Code Flow รองรับพารามิเตอร์ PKCE |
| `POST` | `/login` / `/register` | ส่งคำขอเข้าสู่ระบบหรือสมัครสมาชิกเพื่อแลกเปลี่ยน Transaction ID |
| `GET/POST`| `/consent` | หน้าจอยินยอมสิทธิ์ (Consent Screen) รับรองการยิง Token กลับไปให้แพลตฟอร์มปลายทาง |
| `POST` | `/token` | แลกเปลี่ยน Code หรือ Credential เป็น Access Token รองรับ 3 Grant Types |
| `GET` | `/userinfo` | ปกป้องโปรไฟล์ผู้ใช้งานด้วย Access Token เพื่อตอบกลับตามมาตรฐาน OIDC |

### 🛑 Session & Security
| Method | Endpoint | รายละเอียด |
| :-: | --- | --- |
| `POST` | `/introspect` | ระบบเครื่องสแกนลายเซ็น (Introspection ตาม RFC 7662) เอาไว้ให้ API ข้างนอกยิงมาตรวจว่า Token นี้ของจริงและหมดอายุไปหรือยัง |
| `GET` | `/logout` | **RP-Initiated Logout**: ลงชื่อออกจากระบบขุดรากถอนโคนของ Session ภายใน OIDC ทั้งหมด |
| `POST` | `/revoke` | ทำลายล้าง `refresh_token` เก่า (ตาม RFC 7009) เวลาแอปฝั่งลูกข่ายต้องการปิดระบบ |

### 🛠️ Admin Zone
| Method | Endpoint | รายละเอียด |
| :-: | --- | --- |
| `GET` | `/admin/dashboard` | หน้าแสดงรายการและการสั่งสร้าง Client Application ใหม่ ปกป้องด้วย Basic Auth |
| `POST` | `/admin/clients/ui` | สร้าง Client ผ่านหน้า Web UI (Form) |
| `POST` | `/admin/clients` | สร้าง Client ผ่าน JSON API |
| `POST` | `/admin/users` | สร้าง User ผ่าน JSON API |

---

## 🔑 Grant Types ที่รองรับ — อธิบายแต่ละประเภท

OAuth 2.0 กำหนด "Grant Type" คือ **วิธีที่ Client จะขอ Access Token** แต่ละวิธีเหมาะกับสถานการณ์ต่างกัน

---

### 1. `authorization_code` — สำหรับ Web App / Mobile มี User

**ใช้เมื่อ:** แอปต้องการให้ User เข้าสู่ระบบ แล้วได้รับ Token ของ User คนนั้น

**ทำไมถึงปลอดภัย:** แอปไม่เคยเห็น Password ของ User เลย เพราะ OIDC Server เป็นคนรับและตรวจสอบ แอปได้แค่ Authorization Code กลับมา แล้วค่อยแลกเป็น Token

```
Browser                Client App              OIDC Server
   │                       │                       │
   │──── คลิก Login ───────▶│                       │
   │                       │──── Redirect ──────────▶│
   │◀──────────────────────────── หน้า Login ────────│
   │──── กรอก Password ─────────────────────────────▶│ ← Password อยู่แค่นี่!
   │◀──────────────── Consent Screen ───────────────│
   │──── กด Allow ──────────────────────────────────▶│
   │◀────────────────── redirect+code ──────────────│
   │──── code กลับมา ──────▶│                       │
   │                       │──── POST /token ───────▶│
   │                       │◀──── Access Token ──────│
```

**ต้องการ PKCE ไหม?**  
- **Public Client** (SPA, Mobile App): **บังคับ** — ป้องกัน Authorization Code Interception
- **Confidential Client** (Web Server, BFF): ส่ง `client_secret` แทนได้

```bash
# Step 1: เริ่ม Authorization Flow
GET /authorize?
  response_type=code
  &client_id=MY_CLIENT
  &redirect_uri=https://app.com/callback
  &scope=openid profile email
  &state=random_csrf_token
  &code_challenge=BASE64URL(SHA256(code_verifier))   ← PKCE
  &code_challenge_method=S256

# Step 2: แลก Code เป็น Token
POST /token
  grant_type=authorization_code
  code=AUTH_CODE
  redirect_uri=https://app.com/callback
  code_verifier=ORIGINAL_RANDOM_STRING             ← PKCE
  client_id=MY_CLIENT
  client_secret=MY_SECRET                          ← Confidential Client เท่านั้น
```

**Response:**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "...",
  "id_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**ตัวอย่าง Use Case:** Sign in with Google, LINE Login, Facebook Login

---

### 2. `refresh_token` — ต่ออายุ Token โดยไม่ต้อง Login ใหม่

**ใช้เมื่อ:** Access Token หมดอายุ ต้องการขอใหม่โดยไม่กวน User ให้ Login ซ้ำ

**ทำไมถึงต้องมี:** Access Token ออกแบบมาให้อายุสั้น (เช่น 1 ชั่วโมง) เพื่อความปลอดภัย แต่ถ้าบังคับให้ Login ใหม่ทุกชั่วโมง User จะรำคาญ Refresh Token จึงเป็นตัวกลางที่อยู่ได้นาน (30 วัน) ใช้แลก Access Token ใหม่เงียบ ๆ

```
Client App              OIDC Server
    │                       │
    │ ── POST /token ───────▶│   grant_type=refresh_token
    │                       │   refresh_token=LONG_LIVED_TOKEN
    │◀── Access Token ───────│   ← Token ชุดใหม่ อายุ 1 ชั่วโมง
    │   (Refresh Token ใหม่)  │   ← Refresh Token หมุนเวียน (Rotation)
```

```bash
POST /token
  grant_type=refresh_token
  refresh_token=REFRESH_TOKEN_STRING
  client_id=MY_CLIENT
  client_secret=MY_SECRET       ← ถ้าเป็น Confidential Client
```

**Response:**
```json
{
  "access_token": "eyJ...ใหม่...",
  "refresh_token": "...ใหม่...",
  "id_token": "eyJ...ใหม่...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

> ⚠️ **Refresh Token Rotation**: ทุกครั้งที่ใช้ Refresh Token จะได้ชุดใหม่กลับมา ของเดิมถูก invalidate ทันที ป้องกัน Token Theft

**ต้องการ Scope `offline_access`:** Client ต้องขอ scope นี้ตอน `/authorize` จึงจะได้ Refresh Token กลับมา

---

### 3. `client_credentials` — สำหรับ Machine-to-Machine (M2M)

**ใช้เมื่อ:** ระบบต้องการคุยกับระบบอื่นโดยตรง ไม่มี User เข้ามาเกี่ยวข้อง เช่น Microservices, Background Jobs, Cron Tasks

**ทำไมถึงต้องมี:** หากใช้ API Key แบบ hardcode ในโค้ด ถ้าหลุดออกไปจะถูกใช้งานได้ตลอดไป `client_credentials` แก้ปัญหานี้ด้วยการออก JWT ที่หมดอายุเองอัตโนมัติ

```
Order Service           OIDC Server         Payment Service
     │                      │                     │
     │── POST /token ───────▶│ client_id+secret    │
     │◀── Access Token ──────│ (อายุ 1 ชั่วโมง)    │
     │                      │                     │
     │── API Call + Bearer ──────────────────────▶│
     │                      │                     │ ตรวจ Token
     │                      │◀─── GET /jwks.json ─│ ด้วย Public Key
     │◀──────────────────────────── Response ──────│
```

```bash
# วิธีที่ 1: Basic Auth (แนะนำ)
curl -X POST http://localhost:8080/token \
  -u "CLIENT_ID:CLIENT_SECRET" \
  -d "grant_type=client_credentials&scope=read:orders"

# วิธีที่ 2: Body Parameters
curl -X POST http://localhost:8080/token \
  -d "grant_type=client_credentials" \
  -d "client_id=CLIENT_ID" \
  -d "client_secret=CLIENT_SECRET" \
  -d "scope=read:orders"
```

**Response:** (ไม่มี `refresh_token` และ `id_token` เพราะไม่มี User)
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read:orders"
}
```

> ⚠️ ต้องการ **Confidential Client เท่านั้น** (ต้องมี `client_secret`)  
> ⚠️ ต้อง tick **`client_credentials`** ใน Grant Types ตอนสร้าง Client ผ่าน Admin Dashboard

**ตัวอย่าง Use Case:** Stripe → ระบบของลูกค้า, GitHub Actions → API, Cron Job → Analytics Service

---

### สรุปเปรียบเทียบ

| | `authorization_code` | `refresh_token` | `client_credentials` |
|---|:---:|:---:|:---:|
| มี User เกี่ยวข้อง | ✅ | ✅ (ต่อจาก auth_code) | ❌ |
| ต้องการ Browser | ✅ | ❌ | ❌ |
| ได้ Access Token | ✅ | ✅ | ✅ |
| ได้ Refresh Token | ✅ (ถ้ามี `offline_access`) | ✅ (ชุดใหม่) | ❌ |
| ได้ ID Token | ✅ (ถ้ามี `openid`) | ✅ | ❌ |
| Client Type | Public / Confidential | Public / Confidential | **Confidential เท่านั้น** |
| `sub` ใน Token | User ID | User ID | **Client ID** |
| Use Case | Login ด้วย User | ต่ออายุ Session | M2M / Service-to-Service |



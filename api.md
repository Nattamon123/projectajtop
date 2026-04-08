# NetWatch — API Documentation 📡

เอกสารฉบับนี้อธิบายรายละเอียดของ API ในระบบ NetWatch ทั้งส่วนของ **REST API** และ **Socket.io** พร้อมระบุตำแหน่งไฟล์และบรรทัดที่ควบคุม Logic นั้นๆ

---

## 🔐 1. Authentication (ระบบยืนยันตัวตน)

### **POST `/api/auth/login`**
ใช้สำหรับการยืนยันตัวตนเพื่อเข้าใช้งานระบบ
- **Server Logic:** `src/routes/auth.js` (บรรทัดที่ 19)
- **Client Request:** `public/js/api.js` (ฟังก์ชัน `nwApi.login`)
- **Request (JSON):** 
  ```json
  {
    "username": "admin",
    "password": "password123"
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "token": "JWT_TOKEN_STRING",
    "user": { "id": "uuid", "username": "admin", "role": "admin" }
  }
  ```

---

## 📊 2. Packets & History (ข้อมูลแพ็กเก็ต)

### **GET `/api/packets/history`**
ดึงข้อมูลประวัติแพ็กเก็ตย้อนหลังจากฐานข้อมูล
- **Server Logic:** `src/routes/packets.js` (บรรทัดที่ 10)
- **Client Request:** `public/js/api.js` (ฟังก์ชัน `nwApi.getHistory`)
- **Query Parameters:** `page`, `limit` (max 500), `protocol`, `appProtocol`, `encrypted`
- **Response:** รายการ Packets พร้อมข้อมูล Pagination

### **GET `/api/packets/stats`**
ดึงข้อมูลสถิติสรุปย้อนหลังในรอบ 1 ชั่วโมง
- **Server Logic:** `src/routes/packets.js` (บรรทัดที่ 46)
- **Response:** สถิติเปอร์เซ็นต์การเข้ารหัส, โปรโตคอล และ Top IPs

---

## 👥 3. User Management (จัดการผู้ใช้ - เฉพาะ Admin)

| Method / Endpoint | Server Logic (File:Line) | Client Request (API function) |
| :--- | :--- | :--- |
| **GET** `/api/users` | `src/routes/users.js:11` | `nwApi.getUsers()` |
| **POST** `/api/users` | `src/routes/users.js:21` | `nwApi.createUser()` |
| **PUT** `/api/users/:id` | `src/routes/users.js:39` | `nwApi.updateUser()` |
| **DELETE** `/api/users/:id` | `src/routes/users.js:63` | `nwApi.deleteUser()` |

---

## ⚡ 4. Socket.io Events (Real-time Controls)

### **⬅️ Client → Server (Requests)**
| Event Name | Server Handler (File:Line) | Client Wrapper (File) |
| :--- | :--- | :--- |
| `capture:getInterfaces` | `src/socket/socketHandler.js:168` | `public/js/api.js` |
| `capture:start` | `src/socket/socketHandler.js:175` | `public/js/api.js` |
| `capture:stop` | `src/socket/socketHandler.js:179` | `public/js/api.js` |
| `stats:reset` | `src/socket/socketHandler.js:187` | `public/js/api.js` |

### **➡️ Server → Client (Data Broadcast)**
| Event Name | Server Dispatcher (File:Line) | คำอธิบาย |
| :--- | :--- | :--- |
| `stats:update` | `src/socket/socketHandler.js:135` | อัปเดตสถิติ KPI ประจำวินาที |
| `packet:batch` | `src/socket/socketHandler.js:134` | ส่งข้อมูล Packet 20 ใบสุดท้ายให้หน้าจอ |
| `capture:status` | `src/socket/socketHandler.js:139` | อัปเดตสถานะการทำงานของ Engine |

---

## 📦 5. Packet Data Format
ข้อมูล Packet แต่ละใบที่ส่งผ่าน API และ Socket จะมีโครงสร้างดังนี้:
- **Defined in Model:** [src/models/Packet.js](file:///d:/topsproject/netwatch/src/models/Packet.js)
```json
{
  "timestamp": "ISO-Date",
  "srcIp": "String",
  "dstIp": "String",
  "srcPort": "Number",
  "dstPort": "Number",
  "protocol": "TCP/UDP/ICMP",
  "appProtocol": "HTTPS/DNS/...",
  "flow": "Request/Response/Data",
  "size": "Number",
  "encrypted": "Boolean",
  "tlsVersion": "String/null"
}
```

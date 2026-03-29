# 🛡️ Log Blockchain — Row-by-Row Hash Chaining

ระบบตรวจสอบความถูกต้องของ MySQL Log โดยใช้ Hash Chain + Ethereum Blockchain เป็น Source of Truth

## สถาปัตยกรรม

```
mysql.general_log ──► ดึงทีละ 1 log ──► SHA-256 Hash Chain ──► INSERT audit_ledger
                                                                       │
                                                                  ครบ 20 แถว?
                                                                   └─ ใช่ → ส่ง Hash ขึ้น Blockchain ⚓
                                                                            เริ่ม Group ใหม่
```

- **Row-by-Row**: แต่ละ log = 1 แถว ใน `audit_ledger` พร้อม hash ที่ร้อยต่อจากแถวก่อนหน้า
- **Anchor ทุก 20 แถว**: hash ตัวสุดท้าย ส่งขึ้น Ethereum Sepolia Smart Contract
- **Audit ทุก 30 วินาที**: re-hash จาก `general_log` จริง → เทียบกับ Blockchain

## การตรวจจับ Tamper

| สถานการณ์ | ผล |
|---|---|
| ลบ log ใน general_log | 🚨 จับได้ |
| แก้ไข log ใน general_log | 🚨 จับได้ |
| แก้/ลบ audit_ledger | 🚨 จับได้ (Blockchain เป็นตัวตัดสิน) |
| แก้ทั้ง 2 ตาราง | 🚨 จับได้ (แก้ Blockchain ไม่ได้) |

## ไฟล์หลัก

| ไฟล์ | คำอธิบาย |
|---|---|
| `server.js` | Backend หลัก — hash chain, audit, API, LINE แจ้งเตือน |
| `frontend/dashboard.html` | Dashboard แสดงผล + Report |
| `contracts/LogStorage.sol` | Smart Contract บน Ethereum Sepolia |
| `scripts/initialSync.js` | Sync log เก่าทั้งหมดเข้า audit_ledger + blockchain |

## วิธีรัน

### 1. ตั้งค่า `.env`
```env
DB_HOST=localhost
DB_USER=root
DB_PASS=1234
DB_NAME=company_db
CONTRACT_ADDRESS=0x...
RPC_URL=https://eth-sepolia.g.alchemy.com/v2/...
PRIVATE_KEY=...
API_KEY=log-audit-secret-2024
LINE_CHANNEL_TOKEN=          # (optional) LINE Messaging API
LINE_USER_ID=                # (optional) ผู้รับแจ้งเตือน
```

### 2. ติดตั้ง Dependencies
```bash
npm install
```

### 3. รัน Server
```bash
node server.js
```

### 4. Initial Sync (ถ้าต้องการ sync log เก่า)
```bash
npx hardhat run scripts/initialSync.js --network sepolia
```

### 5. เปิด Dashboard
เปิด `frontend/dashboard.html` ในเบราว์เซอร์

## API Endpoints

| Method | Path | คำอธิบาย |
|---|---|---|
| GET | `/api/get-status` | ข้อมูล audit_ledger + pagination |
| GET | `/api/report` | Report เทียบ audit hash vs blockchain |
| GET | `/api/config` | Contract address + RPC URL |
| POST | `/api/ingest` | รับ log จากภายนอก (multi-source) |

### ตัวอย่าง `/api/ingest`
```bash
curl -X POST http://localhost:3000/api/ingest \
  -H "Content-Type: application/json" \
  -H "x-api-key: log-audit-secret-2024" \
  -d '{"log_source": "nginx", "message": "GET /api 200"}'
```

## Tech Stack

- **Backend**: Node.js, Express
- **Database**: MySQL (`general_log` + `audit_ledger`)
- **Blockchain**: Ethereum Sepolia, Solidity, ethers.js
- **Frontend**: HTML, Tailwind CSS
- **แจ้งเตือน**: LINE Messaging API

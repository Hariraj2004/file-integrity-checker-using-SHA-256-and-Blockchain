# File Integrity Checker — SHA-256 + Blockchain
**Backend:** Flask + SQLite  
**Frontend:** 3D Cyberpunk UI (HTML/CSS/JS)  
**Project by:** Jayabharath, Hariraj, Harish, Thilip Haaran  
**Guide:** RAMYA.S, AP/CSE(CS) | Academic Year 2022–2026

---

## Overview

To make the dashboard more informative, I introduced a file change percentage indicator. This feature compares the original and modified file content and visually displays the severity of changes, while blockchain-backed hash logging preserves integrity verification.

---

## Project Structure

```
fileintegrity/
├── app.py              ← Flask backend (main entry point)
├── requirements.txt    ← Python dependencies
├── integrity.db        ← SQLite database (auto-created)
├── uploads/            ← Stored registered files (auto-created)
└── static/
    └── index.html      ← 3D frontend UI
```

---

## Setup & Run

### 1. Install dependencies
```bash
pip install flask werkzeug
```

### 2. Start the server
```bash
python app.py
```

### 3. Open the app
Visit → **http://localhost:5000**

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET  | `/api/health`              | Server health check |
| GET  | `/api/stats`               | Dashboard statistics |
| GET  | `/api/files`               | List all registered files |
| POST | `/api/files/register`      | Register / re-check a file |
| DELETE | `/api/files/<id>`        | Remove file from monitoring |
| POST | `/api/files/<id>/recheck`  | Re-hash server-stored file |
| POST | `/api/verify`              | Verify uploaded file vs stored hash |
| GET  | `/api/verify/hash?hash=`   | Lookup hash in blockchain |
| GET  | `/api/verify/log`          | Verification history |
| GET  | `/api/blockchain`          | Full blockchain ledger |
| GET  | `/api/blockchain/validate` | Validate chain integrity |
| GET  | `/api/alerts`              | Security event log |
| DELETE | `/api/alerts`            | Clear alert log |

---

## How It Works

1. **Register** — Upload a file → SHA-256 hash computed server-side → hash stored in SQLite → new blockchain block created.
2. **Re-upload same file** — If hash matches: verified OK. If hash differs: TAMPER ALERT fired.
3. **Verify tab** — Upload any file → compare its live hash against the stored blockchain record.
4. **Blockchain** — Each block contains: `block_index`, `timestamp`, `data`, `prev_hash`, `block_hash`. Immutable chain ensures stored hashes cannot be silently modified.
5. **Validate Chain** — Recomputes expected hashes for all blocks and checks prev_hash linkage.

---

## Database Tables

- `files` — registered file records (name, size, SHA-256, status, block ref)
- `blocks` — blockchain ledger (index, data, prev_hash, block_hash, timestamp)
- `alerts` — security event log (type, message, timestamp)
- `verify_log` — history of all verifications performed

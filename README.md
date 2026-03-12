# OJS Integrated Security Scanner

Sistem keamanan terintegrasi untuk website jurnal berbasis **Open Journal Systems (OJS)**.
Scanner otomatis mendeteksi celah keamanan menggunakan OWASP ZAP dan Nikto,
menghitung risk score, dan menyimpan hasil ke database.

---

## 🐳 Cara Menjalankan

### Prasyarat
- Docker Engine
- Docker Compose

### Clone & Jalankan
```bash
git clone https://github.com/username/Capstone.git
cd Capstone
docker compose up --build
```

### Akses
| Service        | URL                        |
|----------------|----------------------------|
| OJS            | http://localhost:8080      |
| Backend API    | http://localhost:8000      |
| API Docs       | http://localhost:8000/docs |
| ZAP API        | http://localhost:8090      |
| phpMyAdmin     | http://localhost:8888      |

---

## 📁 Struktur Project

```
Capstone/
├── docker-compose.yml       # Konfigurasi semua container
├── backend/
│   ├── Dockerfile           # Build container backend
│   ├── requirements.txt     # Library Python
│   ├── main.py              # FastAPI app & endpoint
│   ├── scanner.py           # Logic trigger ZAP & Nikto
│   ├── risk_engine.py       # Kalkulasi risk score
│   └── database.py          # Koneksi & operasi MySQL
├── ojs/
│   └── Dockerfile           # Build container OJS
└── dashboard/
```

---

## 🔌 API Endpoint

| Method | Endpoint      | Fungsi                        |
|--------|---------------|-------------------------------|
| POST   | /scan/zap     | Jalankan ZAP scan             |
| POST   | /scan/nikto   | Jalankan Nikto scan           |
| POST   | /scan/all     | Jalankan semua scanner        |
| GET    | /results      | Ambil semua hasil scan        |

---

## 👥 Tim
Capstone Project — [Nama Tim / Universitas]
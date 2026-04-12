# Masterplan WAF as a Service — v2.0
## Web Application Firewall dengan Multi-Tenant User Management

---

**Judul Penelitian:**
*Web Application Firewall* (WAF) berbasis ModSecurity dan Reverse Proxy untuk Mitigasi HTTP Referer *Bypass*, *Scraping*, dan *Hotlinking* — dengan Sistem Manajemen Multi-Tenant Berbasis Layanan

**Penulis:** Taqiya Nabilla Nathania Afnani — NIM 2221101859
**Program Studi:** Rekayasa Keamanan Siber
**Institusi:** Politeknik Siber dan Sandi Negara (PSSN)
**Tahun:** 2026
**Pembimbing:** Dimas Febriyan Priambodo, M.Cs. — NIP. 198802282019021002

---

## Daftar Isi

1. [Perbaruan dari Versi Sebelumnya](#1-perbaruan-dari-versi-sebelumnya)
2. [Arsitektur Sistem v2.0](#2-arsitektur-sistem-v20)
3. [Komponen Sistem](#3-komponen-sistem)
4. [Alur Pengguna](#4-alur-pengguna)
5. [Database Schema](#5-database-schema)
6. [API Endpoints](#6-api-endpoints)
7. [Struktur Proyek](#7-struktur-proyek)
8. [Metodologi DSRM — Update](#8-metodologi-dsrm--update)
9. [Cara Menjalankan](#9-cara-menjalankan)
10. [Metrik Evaluasi](#10-metrik-evaluasi)
11. [Timeline](#11-timeline)

---

## 1. Perbaruan dari Versi Sebelumnya

Versi 2.0 menambahkan lapisan **User Management** dan **Multi-Tenant Origin Server** di atas sistem WAF yang sudah ada:

| Fitur | v1.0 | v2.0 |
|-------|-------|-------|
| WAF Engine (ModSecurity + Nginx) | ✅ | ✅ |
| OWASP CRS Rules | ✅ | ✅ |
| Anti-Scraping | ✅ | ✅ |
| Anti-Hotlinking | ✅ | ✅ |
| Referer Bypass Detection | ✅ | ✅ |
| Dashboard Monitoring | ✅ | ✅ |
| Register & Login (JWT) | ❌ | ✅ |
| Manajemen Origin Server per User | ❌ | ✅ |
| Dynamic Nginx Config (per domain) | ❌ | ✅ |
| ABR/FPR/FNR per Site | ❌ | ✅ |
| Multi-tenant (banyak user, banyak domain) | ❌ | ✅ |
| PostgreSQL Database | ❌ | ✅ |

---

## 2. Arsitektur Sistem v2.0

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         WAF SaaS Platform                               │
│                                                                         │
│  ┌──────────────┐    ┌─────────────────┐    ┌─────────────────────┐   │
│  │   Frontend   │    │  Backend API    │    │    PostgreSQL DB     │   │
│  │  (React SPA) │◄──►│  (Flask + JWT)  │◄──►│  users, sites, logs │   │
│  │  Login/Reg   │    │  /api/auth      │    └─────────────────────┘   │
│  │  Site CRUD   │    │  /api/sites     │                               │
│  │  Dashboard   │    │  /api/metrics   │                               │
│  └──────────────┘    │  /api/rules     │                               │
│         ▲            └────────┬────────┘                               │
│         │                     │ Generate Nginx config                   │
│         │            ┌────────▼────────────────────────────────────┐   │
│         │            │         Nginx + ModSecurity WAF Gateway     │   │
│         │            │                                             │   │
│         └────────────│  waf.local → Dashboard UI                  │   │
│                      │  *.domain.com → Origin Server (per user)   │   │
│                      │                                             │   │
│                      │  ModSecurity:                               │   │
│                      │  - OWASP CRS Rules                         │   │
│                      │  - Anti-Scraping                           │   │
│                      │  - Anti-Hotlinking                         │   │
│                      │  - Referer Bypass Detection                │   │
│                      │  - Anomaly Scoring Threshold               │   │
│                      └──────────────────┬──────────────────────────┘   │
└─────────────────────────────────────────│────────────────────────────────┘
                                          │
                            ┌─────────────┼──────────────┐
                            ▼             ▼              ▼
                      Origin Server  Origin Server  Origin Server
                      (User A - app) (User B - app) (User C - app)
```

### Alur Request

```
[Browser User A]
      │
      ▼
[WAF Gateway: Nginx + ModSecurity]
      │
      ├── waf.local/        → Frontend Dashboard (React)
      │
      ├── waf.local/api/    → Backend Flask API
      │
      └── userdomain.com/   → Proses WAF:
                               1. Validasi Referer (anti-bypass)
                               2. Cek User-Agent (anti-scraping)
                               3. Hotlink protection
                               4. ModSecurity Layer 7 inspection
                               5. Anomaly scoring
                               └─ PASS → Origin Server User A
                               └─ BLOCK → 403 + catat ke DB
```

---

## 3. Komponen Sistem

### 3.1 Frontend (React SPA)

Halaman yang tersedia:

| Halaman | Route | Deskripsi |
|---------|-------|-----------|
| Login | `/` | Form login email/username + password |
| Register | `/` (toggle) | Form registrasi akun baru |
| Dashboard | `/dashboard` | Ringkasan semua site + statistik |
| Website Saya | `/sites` | Daftar domain yang dilindungi |
| Detail Site | `/sites/:id` | Metrik, log, dan pengaturan satu site |
| Profil | `/profile` | Edit data akun dan password |

### 3.2 Backend API (Flask)

| Blueprint | Prefix | Fungsi |
|-----------|--------|--------|
| `auth_bp` | `/api/auth` | Register, login, refresh token, profil |
| `sites_bp` | `/api/sites` | CRUD origin server, toggle WAF |
| `metrics_bp` | `/api/metrics` | ABR/FPR/FNR per site, ingest log |
| `rules_bp` | `/api/rules` | Get/update WAF rules per site |

### 3.3 WAF Engine

- **Nginx** — Reverse proxy, rate limiting, hotlink protection
- **ModSecurity v3** — Layer 7 inspection, anomaly scoring
- **OWASP CRS v4** — Ruleset lengkap OWASP Top 10
- **Custom Rules** — Referer bypass, anti-scraping, anti-hotlinking

### 3.4 Database (PostgreSQL)

Tiga tabel utama:

```
users          — Akun pengguna platform
sites          — Domain/origin server yang didaftarkan
attack_logs    — Log serangan per site
```

---

## 4. Alur Pengguna

```
[User baru]
    │
    ▼
Register (email, username, password)
    │
    ▼
Login → Dapat JWT Access Token
    │
    ▼
Dashboard — lihat ringkasan (kosong jika belum ada site)
    │
    ▼
"+ Tambah Website"
    │
    ├─ Isi: Nama, Domain (myapp.com), Origin URL (http://192.168.x.x:8080)
    ├─ Pilih: Rate Limit, Paranoia Level, Anomaly Threshold
    └─ Toggle: Anti-Scraping, Anti-Hotlinking, Referer Check
    │
    ▼
Backend:
    ├─ Simpan ke tabel sites
    ├─ Generate /etc/nginx/conf.d/site_{uuid}.conf
    ├─ Generate /etc/nginx/modsecurity/sites/{uuid}.conf
    └─ nginx -s reload (apply config tanpa downtime)
    │
    ▼
WAF aktif untuk domain user tersebut
    │
    ▼
Setiap request ke domain diproses WAF:
    ├─ Diblokir → catat di attack_logs (via log parser)
    └─ Diteruskan → ke origin server user
    │
    ▼
User lihat Dashboard Site:
    ├─ ABR, FPR, FNR
    ├─ Distribusi serangan (SQLi, XSS, Scraping, dll)
    ├─ Log serangan terbaru
    └─ Response Time mean/P95/P99
```

---

## 5. Database Schema

### Tabel `users`

| Kolom | Tipe | Keterangan |
|-------|------|------------|
| id | UUID | Primary key |
| email | VARCHAR(255) | Unik, index |
| username | VARCHAR(80) | Unik |
| password | VARCHAR(255) | Bcrypt hash |
| full_name | VARCHAR(150) | Opsional |
| role | VARCHAR(20) | `user` atau `admin` |
| is_active | BOOLEAN | Default true |
| created_at | DATETIME | Waktu registrasi |

### Tabel `sites`

| Kolom | Tipe | Keterangan |
|-------|------|------------|
| id | UUID | Primary key |
| user_id | UUID | Foreign key → users |
| name | VARCHAR(100) | Nama tampilan |
| domain | VARCHAR(255) | Domain unik (myapp.com) |
| origin_url | VARCHAR(500) | URL server asli |
| waf_enabled | BOOLEAN | WAF aktif/nonaktif |
| paranoia_level | INT | 1–4 |
| anomaly_threshold | INT | Score threshold (default 5) |
| block_scraping | BOOLEAN | Toggle anti-scraping |
| block_hotlinking | BOOLEAN | Toggle anti-hotlink |
| block_referer_bypass | BOOLEAN | Toggle referer validation |
| rate_limit_rpm | INT | Max request/menit |
| nginx_conf_file | VARCHAR | Path config Nginx |
| modsec_conf_file | VARCHAR | Path config ModSecurity |

### Tabel `attack_logs`

| Kolom | Tipe | Keterangan |
|-------|------|------------|
| id | UUID | Primary key |
| site_id | UUID | Foreign key → sites |
| client_ip | VARCHAR(45) | IP penyerang |
| method | VARCHAR(10) | GET/POST/dll |
| uri | VARCHAR(500) | Path yang diserang |
| attack_type | VARCHAR(50) | SQLi, XSS, Scraping, dll |
| severity | VARCHAR(20) | low/medium/high/critical |
| action | VARCHAR(20) | blocked/passed |
| anomaly_score | INT | Score ModSecurity |
| message | TEXT | Pesan rule |
| status_code | INT | HTTP response code |
| response_time_ms | FLOAT | Latensi |
| timestamp | DATETIME | Waktu kejadian |

---

## 6. API Endpoints

### Auth (`/api/auth`)

| Method | Endpoint | Deskripsi | Auth |
|--------|----------|-----------|------|
| POST | `/register` | Registrasi akun baru | ❌ |
| POST | `/login` | Login, dapat JWT token | ❌ |
| POST | `/refresh` | Refresh access token | ✅ refresh |
| GET | `/me` | Profil user aktif | ✅ |
| PUT | `/profile` | Update profil/password | ✅ |

### Sites (`/api/sites`)

| Method | Endpoint | Deskripsi | Auth |
|--------|----------|-----------|------|
| GET | `/` | Daftar semua site user | ✅ |
| POST | `/` | Tambah site baru | ✅ |
| GET | `/:id` | Detail satu site | ✅ |
| PUT | `/:id` | Update site | ✅ |
| DELETE | `/:id` | Hapus site | ✅ |
| POST | `/:id/toggle-waf` | Aktifkan/nonaktifkan WAF | ✅ |
| GET | `/:id/logs` | Log serangan site | ✅ |

### Metrics (`/api/metrics`)

| Method | Endpoint | Deskripsi | Auth |
|--------|----------|-----------|------|
| GET | `/overview` | Ringkasan semua site | ✅ |
| GET | `/site/:id` | Metrik detail (ABR/FPR/FNR) | ✅ |
| POST | `/site/:id/ingest` | Ingest log dari ModSecurity | ✅ |
| POST | `/site/:id/demo-attack` | Generate data demo | ✅ |

### Rules (`/api/rules`)

| Method | Endpoint | Deskripsi | Auth |
|--------|----------|-----------|------|
| GET | `/site/:id` | Konfigurasi WAF rules | ✅ |
| PUT | `/site/:id` | Update rules per site | ✅ |

---

## 7. Struktur Proyek

```
waf-saas-final/
├── .env                          # Environment variables
├── docker-compose.yml            # Orkestrasi semua service
│
├── backend/                      # Flask API
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── wsgi.py                   # Entry point Gunicorn
│   └── app/
│       ├── __init__.py           # App factory
│       ├── models.py             # User, Site, AttackLog
│       ├── routes/
│       │   ├── auth.py           # Register, login, profil
│       │   ├── sites.py          # CRUD origin server
│       │   ├── metrics.py        # ABR/FPR/FNR calculation
│       │   └── rules.py          # WAF rules management
│       └── services/
│           └── nginx_generator.py # Dynamic Nginx config gen
│
├── frontend/                     # React SPA
│   ├── Dockerfile
│   ├── nginx.conf
│   └── index.html                # Single-file React app (vanilla JS)
│
├── docker/
│   └── Dockerfile.waf            # Nginx + ModSecurity build
│
├── nginx/
│   ├── nginx.conf                # Main Nginx config
│   └── conf.d/
│       └── proxy_params.conf     # Shared proxy settings
│
├── modsecurity/
│   ├── modsecurity.conf          # Engine config (SecRuleEngine On)
│   ├── main.conf                 # Include semua ruleset
│   ├── crs-setup/
│   │   └── crs-setup.conf        # OWASP CRS tuning
│   └── custom-rules/
│       ├── 1000-referer-bypass.conf
│       ├── 1001-anti-scraping.conf
│       ├── 1002-anti-hotlinking.conf
│       ├── 1003-anomaly-scoring.conf
│       └── 1004-whitelist.conf
│
└── scripts/
    ├── gen_ssl.sh                # Generate SSL certificate
    ├── setup/
    │   └── init.sql              # PostgreSQL initialization
    └── testing/
        ├── security_test.py      # Security test (ABR/FPR/FNR)
        ├── load_test.py          # Load test (Throughput/RT)
        └── comparative.py        # Comparative testing
```

---

## 8. Metodologi DSRM — Update

### Fase 1 — Awareness of Problem (Diperbarui)

Selain masalah WAF konvensional yang sudah diidentifikasi sebelumnya, ditambahkan:
- WAF konvensional tidak memiliki antarmuka manajemen multi-tenant
- Admin harus edit file config langsung di server — tidak user-friendly
- Tidak ada visibilitas per-domain untuk mengetahui serangan apa yang paling sering terjadi

### Fase 2 — Suggestion (Diperbarui)

Solusi ditambahkan:
- **User Management** berbasis JWT (register/login/refresh)
- **Origin Server Management** — user daftarkan domain mereka sendiri
- **Dynamic Config Generation** — backend generate Nginx + ModSecurity config otomatis
- **Per-Site Dashboard** — metrik ABR/FPR/FNR per domain

### Fase 3 — Development (Komponen Baru)

**Backend Flask API:**

```python
# Register user baru
POST /api/auth/register
Body: { email, username, password, full_name }
Response: { user, access_token, refresh_token }

# Tambah site baru
POST /api/sites/
Headers: Authorization: Bearer <token>
Body: {
  name: "Toko Online",
  domain: "myapp.com",
  origin_url: "http://192.168.1.10:8080",
  rate_limit_rpm: 100,
  anomaly_threshold: 5,
  paranoia_level: 1,
  block_scraping: true,
  block_hotlinking: true,
  block_referer_bypass: true
}
```

**Dynamic Nginx Config (di-generate per site):**

```nginx
# Auto-generated untuk myapp.com
upstream origin_abc123 {
    server 192.168.1.10:8080;
}

server {
    listen 443 ssl;
    server_name myapp.com www.myapp.com;
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsecurity/sites/{site_id}.conf;

    # Anti-hotlinking
    location ~* \.(jpg|png|mp4|pdf)$ {
        valid_referers none blocked server_names myapp.com;
        if ($invalid_referer) { return 403; }
        proxy_pass http://origin_abc123;
    }
}
```

### Fase 4 — Evaluation (Tidak Berubah)

Metrik yang sama: ABR, FPR, FNR, Throughput, Response Time.
Sekarang metrik dihitung per-site dari database `attack_logs`.

### Fase 5 — Conclusion

Ditambahkan ekspektasi: sistem dapat digunakan sebagai proof-of-concept WAF multi-tenant berbasis open source yang layak sebagai alternatif Cloudflare/AWS WAF untuk skala penelitian.

---

## 9. Cara Menjalankan

### Prasyarat

```bash
# Ubuntu 24.04 LTS atau Docker Desktop
docker --version     # >= 24.x
docker-compose --version  # >= 2.x
openssl              # untuk SSL
```

### Langkah Cepat

```bash
# 1. Clone / extract project
cd waf-saas-final

# 2. Generate SSL certificate
chmod +x scripts/gen_ssl.sh
bash scripts/gen_ssl.sh

# 3. Build & jalankan semua container
docker-compose up -d --build

# 4. Cek semua container berjalan
docker-compose ps

# 5. Akses aplikasi
# Dashboard: http://localhost  (atau http://waf.local)
# API Health: http://localhost/api/health
```

### Register & Mulai

```
1. Buka http://localhost
2. Klik "Daftar sekarang"
3. Isi: nama, email, username, password
4. Setelah masuk → klik "+ Tambah Website"
5. Isi domain dan origin server URL
6. WAF otomatis aktif!
7. Klik "Generate Demo Data" untuk simulasi serangan
8. Lihat metrik ABR/FPR/FNR di Dashboard Site
```

### Troubleshooting

```bash
# Lihat log backend
docker logs waf-backend -f

# Lihat log WAF gateway
docker logs waf-gateway -f

# Masuk ke container backend
docker exec -it waf-backend bash

# Rebuild satu service
docker-compose up -d --build backend

# Reset database
docker-compose down -v
docker-compose up -d --build
```

---

## 10. Metrik Evaluasi

### Definisi

```
ABR = (Serangan Diblokir / Total Serangan) × 100%
FPR = (Request Sah Diblokir / Total Request Sah) × 100%
FNR = (Serangan Lolos / Total Serangan) × 100%
```

### Target

| Metrik | Baseline WAF | Enhanced WAF | Target |
|--------|-------------|-------------|--------|
| ABR Overall | ~72% | >90% | Enhanced > Baseline |
| FPR | <2% | <1% | Semakin rendah |
| FNR | <15% | <5% | Semakin rendah |
| Throughput | — | >500 req/s | Stabil |
| Response Time Mean | — | <50 ms | Rendah |

### Script Evaluasi

```bash
# Security test (ABR/FPR/FNR)
python3 scripts/testing/security_test.py \
  --target http://localhost \
  --output hasil_enhanced.json

# Load test
python3 scripts/testing/load_test.py \
  --target http://localhost \
  --requests 10000 \
  --concurrency 100 \
  --output hasil_load.json

# Comparative testing (Tabel 3.4)
python3 scripts/testing/comparative.py \
  --baseline-sec hasil_baseline.json \
  --enhanced-sec hasil_enhanced.json \
  --baseline-load load_baseline.json \
  --enhanced-load load_enhanced.json
```

---

## 11. Timeline

| Bulan | Fase DSRM | Kegiatan |
|-------|-----------|----------|
| 1 | Awareness | Studi literatur, identifikasi masalah |
| 1–2 | Suggestion | Desain arsitektur v2.0, ERD, API spec |
| 2–3 | Development | Backend API, Frontend, WAF Engine, integrasi |
| 3–4 | Evaluation | Functional test, load test, security test, comparative |
| 4–5 | Conclusion | Analisis hasil, penulisan laporan TA |

### Milestone

- [ ] M1 — Arsitektur v2.0 disetujui pembimbing
- [ ] M2 — Backend API (auth + sites) selesai
- [ ] M3 — Frontend (register/login/dashboard) selesai
- [ ] M4 — WAF engine terintegrasi dengan dynamic config
- [ ] M5 — Functional test semua fitur PASS
- [ ] M6 — Load test & security test selesai
- [ ] M7 — Comparative testing Baseline vs Enhanced
- [ ] M8 — Laporan TA final

---

## Referensi

- BSSN Lanskap Keamanan Siber Indonesia 2024
- OWASP Top 10 Web Application Security Risks 2021
- OWASP ModSecurity Core Rule Set (CRS) v4
- Design Science Research Methodology (DSRM) — Peffers et al.
- RFC 7231 — HTTP/1.1 Semantics (Referer header)
- Flask-JWT-Extended Documentation
- ModSecurity v3 Reference Manual

---

*Dokumen ini adalah masterplan versi 2.0 dari Proposal Tugas Akhir
Taqiya Nabilla Nathania Afnani (2221101859) — PSSN 2026*

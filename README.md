# ShieldWAF — WAF as a Service

**Tugas Akhir — Taqiya Nabilla Nathania Afnani (2221101859)**
Rekayasa Keamanan Siber — Politeknik Siber dan Sandi Negara (PSSN) 2026

WAF berbasis ModSecurity + Nginx dengan sistem manajemen multi-tenant:
register/login, tambah domain, dan monitoring serangan per site.

---

## Fitur Utama

- Register & Login dengan JWT authentication
- Tambah website/domain yang ingin dilindungi (seperti Cloudflare)
- WAF otomatis aktif: anti-SQLi, XSS, Scraping, Hotlinking, Referer Bypass
- Dashboard metrik per site: ABR, FPR, FNR, Response Time
- Log serangan real-time per domain
- Konfigurasi Nginx di-generate otomatis per site

---

## Cara Cepat Menjalankan (Full Stack)

### 1. Generate SSL

```bash
chmod +x scripts/gen_ssl.sh && bash scripts/gen_ssl.sh
```

### 2. Jalankan dengan Docker

```bash
docker-compose up -d --build
```

### 3. Buka Browser

```
http://localhost
```

Klik **Daftar sekarang** → isi form → tambah website → WAF aktif!

---

## Deploy ke ClawCloud (Backend API Only)

Untuk deploy hanya **Backend API** ke ClawCloud (PaaS), ikuti langkah berikut.

### Build & Start Command

ClawCloud akan otomatis detect `Dockerfile` di root repository.

| Setting | Value |
|---------|-------|
| **Dockerfile path** | `Dockerfile` (root) |
| **Port** | `8000` (atau set via env `PORT`) |
| **Health check path** | `/health` |

### Required Environment Variables

Set variabel berikut di dashboard ClawCloud → **Environment Variables**:

| Variable | Contoh | Keterangan |
|----------|--------|------------|
| `PORT` | `8000` | Port yang didengarkan server (ClawCloud inject otomatis) |
| `DATABASE_URL` | `postgresql://user:pass@host:5432/db` | Koneksi PostgreSQL (wajib) |
| `SECRET_KEY` | `random-string-min-32-chars` | Flask secret key (wajib) |
| `JWT_SECRET_KEY` | `random-string-min-32-chars` | JWT signing key (wajib) |
| `NGINX_CONF_DIR` | `/tmp/waf-nginx-sites` | Dir untuk config Nginx yang di-generate |
| `MODSEC_RULES_DIR` | `/tmp/waf-modsec-sites` | Dir untuk rules ModSecurity yang di-generate |
| `LOG_DIR` | `/tmp/waf-logs` | Dir untuk log ModSecurity |

> **Catatan:** Salin `.env.example` ke `.env` untuk development lokal.

### Langkah Deploy di ClawCloud

1. Buka dashboard ClawCloud → **New App**
2. Pilih **Deploy from GitHub** → pilih repo `dhimazyusuf19/waf-service`
3. ClawCloud otomatis detect `Dockerfile` di root
4. Set environment variables di atas
5. Klik **Deploy**

### Start Command Manual (tanpa Docker)

Jika ClawCloud tidak pakai Docker:

```bash
# Build command
pip install -r backend/requirements.txt

# Start command
cd backend && gunicorn --bind 0.0.0.0:${PORT:-8000} --workers 4 --timeout 120 wsgi:app
```

### Health Check

API menyediakan endpoint health check untuk platform monitoring:

```
GET /health
```

Response:
```json
{"status": "ok", "service": "WAF SaaS API", "version": "1.0.0"}
```

### ClawCloud Overview page: checking status and public URL

Setelah deploy, buka halaman **Overview** service di dashboard ClawCloud. Berikut cara membaca informasi yang tampil:

#### Status Service

Di bagian atas halaman terdapat status service:

| Status | Arti |
|--------|------|
| **Creating** | Container sedang dibuat atau belum berhasil start. Tunggu beberapa saat, lalu cek tab **Logs** jika status tidak berubah. |
| **Running** | Service sudah berjalan normal. |
| **Error / Failed** | Service gagal start — buka tab **Logs** untuk melihat pesan error. |

> **Tip:** Jika status tetap *Creating* lama, periksa tab **Logs** untuk error seperti port mismatch, dependency missing, atau environment variable yang belum di-set.

#### Bagian Network — Port Mapping & Alamat

Di bagian **Network** (contoh: "Network (1)"), ClawCloud menampilkan pemetaan port dan alamat akses service:

| Field | Contoh | Keterangan |
|-------|--------|------------|
| **Port** | `80` | Port yang di-expose ke publik. Pastikan aplikasi listen di port yang sesuai (set via env `PORT`). |
| **Private Address** | `http://waf.ns-xxxxxxxx.svc.cluster.local:80` | URL internal cluster — dipakai antar-service di dalam ClawCloud (tidak bisa diakses dari luar). |
| **Public Address** | `https://xxxxxxxxxxxxxx.ap-southeast-1.clawcloudrun.com` | URL publik yang bisa diakses dari internet. Gunakan ini untuk membuka API atau mengisi konfigurasi reverse proxy. |

**Langkah verifikasi setelah deploy:**

1. Pastikan status berubah dari *Creating* → *Running*.
2. Salin **Public Address** dari bagian Network.
3. Buka URL tersebut di browser atau dengan `curl`:
   ```bash
   curl https://<public-address>/health
   ```
   Respons yang diharapkan:
   ```json
   {"status": "ok", "service": "WAF SaaS API", "version": "1.0.0"}
   ```
4. Jika belum bisa diakses saat status masih *Creating*, tunggu hingga status *Running* baru coba lagi.

---

## Struktur Proyek

```
waf-saas-final/
├── backend/          Flask API (auth, sites, metrics, rules)
├── frontend/         React SPA (login, register, dashboard)
├── docker/           Dockerfile WAF (Nginx + ModSecurity)
├── nginx/            Konfigurasi Nginx
├── modsecurity/      Custom rules + OWASP CRS setup
├── scripts/          SSL generation + testing scripts
├── Dockerfile        Root Dockerfile untuk ClawCloud deployment
├── .dockerignore     Docker build exclusions
├── .env.example      Template environment variables
├── docker-compose.yml
├── MASTERPLAN.md     Masterplan lengkap penelitian
└── README.md
```

---

## API Endpoints

| Method | Endpoint | Deskripsi |
|--------|----------|-----------|
| GET | `/health` | Health check (platform monitoring) |
| POST | `/api/auth/register` | Daftar akun baru |
| POST | `/api/auth/login` | Login, dapat JWT |
| GET | `/api/auth/me` | Profil user aktif |
| GET | `/api/sites/` | Daftar website user |
| POST | `/api/sites/` | Tambah website baru |
| DELETE | `/api/sites/:id` | Hapus website |
| GET | `/api/metrics/overview` | Ringkasan semua site |
| GET | `/api/metrics/site/:id` | Metrik ABR/FPR/FNR |
| POST | `/api/metrics/site/:id/demo-attack` | Generate demo data |

---

## Pengujian Evaluasi (Fase 4)

```bash
# Security test
python3 scripts/testing/security_test.py --target http://localhost

# Load test
python3 scripts/testing/load_test.py --target http://localhost \
  --requests 10000 --concurrency 100

# Comparative testing
python3 scripts/testing/comparative.py \
  --baseline-sec baseline_security.json \
  --enhanced-sec enhanced_security.json \
  --baseline-load baseline_load.json \
  --enhanced-load enhanced_load.json
```

---

## Stack Teknologi

| Layer | Teknologi |
|-------|-----------|
| Frontend | Vanilla JS (React-like, no build tool) |
| Backend | Python Flask + SQLAlchemy + JWT |
| Database | PostgreSQL 16 |
| WAF Engine | Nginx + ModSecurity v3 |
| Ruleset | OWASP CRS v4 + Custom Rules |
| Container | Docker + Docker Compose |

---

*PSSN 2026 — Rekayasa Keamanan Siber*

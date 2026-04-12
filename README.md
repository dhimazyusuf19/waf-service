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

## Cara Cepat Menjalankan

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

## Struktur Proyek

```
waf-saas-final/
├── backend/          Flask API (auth, sites, metrics, rules)
├── frontend/         React SPA (login, register, dashboard)
├── docker/           Dockerfile WAF (Nginx + ModSecurity)
├── nginx/            Konfigurasi Nginx
├── modsecurity/      Custom rules + OWASP CRS setup
├── scripts/          SSL generation + testing scripts
├── docker-compose.yml
├── .env
├── MASTERPLAN.md     Masterplan lengkap penelitian
└── README.md
```

---

## API Endpoints

| Method | Endpoint | Deskripsi |
|--------|----------|-----------|
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

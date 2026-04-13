# ClawCloud: Pilih Docker vs Python Runtime

Panduan ini menjelaskan cara menentukan mode deploy yang tersedia di dashboard **ClawCloud** dan cara mengonfigurasi masing-masing opsi untuk repo `waf-service` ini.

---

## Daftar Isi

1. [Cara Mengidentifikasi Mode Deploy di Dashboard ClawCloud](#1-cara-mengidentifikasi-mode-deploy-di-dashboard-clawcloud)
2. [Opsi A — Deploy via Dockerfile (Direkomendasikan)](#2-opsi-a--deploy-via-dockerfile-direkomendasikan)
3. [Opsi B — Deploy via Python Runtime (Build + Start Command)](#3-opsi-b--deploy-via-python-runtime-build--start-command)
4. [Contoh Build & Start Command untuk Framework Python](#4-contoh-build--start-command-untuk-framework-python)
5. [Environment Variables yang Dibutuhkan](#5-environment-variables-yang-dibutuhkan)
6. [Troubleshooting](#6-troubleshooting)

---

## 1. Cara Mengidentifikasi Mode Deploy di Dashboard ClawCloud

Setelah kamu login ke [ClawCloud](https://clawcloud.com) dan membuat app baru, ikuti langkah berikut untuk mengetahui mode deploy apa yang tersedia:

### Langkah-langkah Pemeriksaan

1. **Buka Dashboard → New App / New Service**
   - Cari tombol **"+ New App"**, **"Create Service"**, atau sejenisnya di halaman utama dashboard.

2. **Pilih "Deploy from GitHub"**
   - Hubungkan akun GitHub kamu jika belum terhubung.
   - Pilih repository: `dhimazyusuf19/waf-service`.

3. **Perhatikan layar konfigurasi — cari indikator berikut:**

   | Yang kamu lihat di UI | Artinya |
   |----------------------|---------|
   | Toggle/checkbox **"Use Dockerfile"** atau **"Docker"** | → Platform mendukung Dockerfile; aktifkan opsi ini |
   | Dropdown **"Runtime"** dengan pilihan **Python 3.x** | → Platform pakai buildpack/native runtime |
   | Field **"Build Command"** dan **"Start Command"** | → Ini mode Python runtime (bukan Docker) |
   | Field **"Dockerfile Path"** | → Platform bisa baca Dockerfile dari repo |
   | Section **"Build Settings"** dengan pilihan **"Buildpack"** vs **"Docker"** | → Kamu bisa pilih salah satu |

4. **Cek tab/bagian "Logs" atau "Detection"** saat pertama kali deploy:
   - Jika log menyebutkan `Detected Dockerfile` atau `Building Docker image…` → mode Docker aktif.
   - Jika log menyebutkan `Installing Python dependencies…` atau `pip install` → mode Python runtime/buildpack aktif.

5. **Jika ada toggle "Dockerfile" tapi tidak ada field build/start command** → gunakan [Opsi A](#2-opsi-a--deploy-via-dockerfile-direkomendasikan).

6. **Jika tidak ada toggle Dockerfile dan hanya ada field build/start command** → gunakan [Opsi B](#3-opsi-b--deploy-via-python-runtime-build--start-command).

---

## 2. Opsi A — Deploy via Dockerfile (Direkomendasikan)

Repo ini sudah memiliki `backend/Dockerfile`. Mode ini adalah yang paling portabel karena semua dependensi (termasuk Nginx + ModSecurity) sudah dikemas di dalam image.

### Konfigurasi di Dashboard ClawCloud

| Setting | Nilai |
|---------|-------|
| **Repository** | `dhimazyusuf19/waf-service` |
| **Branch** | `main` (atau branch yang diinginkan) |
| **Root Directory / Context** | `backend` |
| **Dockerfile Path** | `backend/Dockerfile` *(atau `Dockerfile` jika root directory sudah di-set ke `backend`)* |
| **Port** | `5000` |

### Apa yang Terjadi

ClawCloud akan:
1. Meng-clone repo.
2. Membaca `backend/Dockerfile`.
3. Menjalankan `docker build` secara otomatis.
4. Mengekspos port `5000` sesuai perintah `EXPOSE 5000` di Dockerfile.
5. Menjalankan container dengan perintah:
   ```
   gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 120 wsgi:app
   ```

### Catatan Penting

- Dockerfile ini menggunakan image `python:3.12-slim` dan menginstal Nginx di dalamnya.
- Pastikan environment variables (lihat [Bagian 5](#5-environment-variables-yang-dibutuhkan)) sudah diset di dashboard ClawCloud sebelum deploy.
- Jika ClawCloud menyediakan variabel `$PORT` secara otomatis dan berbeda dari `5000`, kamu perlu mengubah CMD di `backend/Dockerfile`:
  ```dockerfile
  CMD gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 4 --timeout 120 wsgi:app
  ```

---

## 3. Opsi B — Deploy via Python Runtime (Build + Start Command)

Gunakan opsi ini jika ClawCloud tidak mendukung Dockerfile atau kamu ingin menggunakan native Python buildpack.

### Konfigurasi di Dashboard ClawCloud

| Setting | Nilai |
|---------|-------|
| **Repository** | `dhimazyusuf19/waf-service` |
| **Branch** | `main` |
| **Root Directory** | `backend` |
| **Runtime** | `Python 3.12` (atau versi Python tertinggi yang tersedia) |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 4 --timeout 120 wsgi:app` |
| **Port** | `5000` (atau sesuai nilai `$PORT` yang di-inject ClawCloud) |

### Langkah-langkah di Dashboard

1. Di bagian **"Build Settings"**, pastikan pilih **"Buildpack"** (bukan Docker).
2. Set **Root Directory** ke `backend` agar ClawCloud menemukan `requirements.txt` dan `wsgi.py` yang benar.
3. Isi **Build Command**:
   ```
   pip install -r requirements.txt
   ```
4. Isi **Start Command**:
   ```
   gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 4 --timeout 120 wsgi:app
   ```
5. Set environment variables (lihat [Bagian 5](#5-environment-variables-yang-dibutuhkan)).
6. Klik **Deploy**.

### Peringatan

> ⚠️ Mode Python runtime **tidak menginstal Nginx dan ModSecurity** karena itu hanya ada di Dockerfile. Jika service ini membutuhkan Nginx/ModSecurity (untuk fitur WAF penuh), **gunakan Opsi A (Dockerfile)**.
>
> Mode ini hanya cocok jika kamu ingin menjalankan **Flask API-nya saja** tanpa lapisan Nginx/ModSecurity.

---

## 4. Contoh Build & Start Command untuk Framework Python

Referensi cepat untuk berbagai framework Python, jika kamu ingin menyesuaikan:

| Framework | Build Command | Start Command |
|-----------|--------------|--------------|
| **Flask + Gunicorn** (repo ini) | `pip install -r requirements.txt` | `gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 4 wsgi:app` |
| **FastAPI + Uvicorn** | `pip install -r requirements.txt` | `uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}` |
| **FastAPI + Gunicorn + Uvicorn workers** | `pip install -r requirements.txt` | `gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:${PORT:-8000}` |
| **Django** | `pip install -r requirements.txt && python manage.py migrate` | `gunicorn project.wsgi:application --bind 0.0.0.0:${PORT:-8000}` |
| **Flask (development)** | `pip install -r requirements.txt` | `flask run --host 0.0.0.0 --port ${PORT:-5000}` |

> 💡 **Catatan**: Selalu gunakan `0.0.0.0` sebagai host (bukan `127.0.0.1` atau `localhost`) agar container bisa menerima traffic dari luar. Gunakan variabel `$PORT` jika platform meng-inject-nya secara dinamis.

---

## 5. Environment Variables yang Dibutuhkan

Set variabel-variabel berikut di bagian **"Environment Variables"** dashboard ClawCloud sebelum deploy:

| Variabel | Contoh Nilai | Keterangan |
|----------|-------------|------------|
| `SECRET_KEY` | `ganti-dengan-string-acak-panjang` | JWT & Flask secret key |
| `DATABASE_URL` | `postgresql://user:pass@host:5432/dbname` | Koneksi ke PostgreSQL |
| `JWT_SECRET_KEY` | `ganti-dengan-string-acak-lain` | Secret khusus JWT |
| `FLASK_ENV` | `production` | Mode Flask |
| `PORT` | `5000` | Port yang di-listen (biasanya di-inject otomatis oleh platform) |

> ⚠️ **Jangan commit file `.env` ke repository**. File `.env` sudah ada di `.gitignore`. Selalu set secret via dashboard platform.

---

## 6. Troubleshooting

### Build gagal: `ModuleNotFoundError`
- Pastikan **Root Directory** di-set ke `backend` sehingga `requirements.txt` ditemukan.
- Pastikan Build Command: `pip install -r requirements.txt` sudah diisi.

### App crash: `Address already in use`
- Cek apakah ada proses lain yang memakai port yang sama. Gunakan variabel `$PORT` yang di-inject platform.

### App tidak bisa diakses dari luar (timeout)
- Pastikan start command menggunakan `--host 0.0.0.0`, bukan `127.0.0.1`.
- Pastikan port yang di-expose sesuai dengan port yang didaftarkan di dashboard ClawCloud.

### Log menampilkan `[WARNING] Worker with pid X was terminated due to signal 9`
- Tambahkan timeout yang lebih panjang: `--timeout 120` (sudah ada di default command repo ini).
- Atau kurangi jumlah workers jika memory terbatas: `--workers 2`.

### Database tidak terhubung
- Pastikan `DATABASE_URL` sudah diset dengan benar di environment variables.
- Pastikan database PostgreSQL sudah berjalan dan bisa diakses dari container ClawCloud.

---

## Ringkasan: Docker vs Python Runtime

| Kriteria | Dockerfile (Opsi A) | Python Runtime (Opsi B) |
|----------|--------------------|-----------------------|
| **Portabilitas** | ✅ Sangat tinggi | ⚠️ Tergantung buildpack platform |
| **Dukungan Nginx + ModSecurity** | ✅ Ya (termasuk dalam image) | ❌ Tidak (hanya Flask API) |
| **Kemudahan setup** | ✅ Otomatis dari Dockerfile | ⚠️ Perlu mengisi build/start command |
| **Kontrol environment** | ✅ Penuh | ⚠️ Terbatas pada yang disediakan platform |
| **Direkomendasikan untuk repo ini** | ✅ **Ya** | Hanya jika Docker tidak tersedia |

---

*Untuk pertanyaan atau kontribusi, buka issue di [GitHub](https://github.com/dhimazyusuf19/waf-service/issues).*

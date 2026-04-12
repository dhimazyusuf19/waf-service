#!/usr/bin/env python3
"""
=============================================================================
Load Testing Script — Fase 4 Evaluasi (Performa)
Taqiya Nabilla Nathania Afnani — PSSN 2026

Mengukur:
  - Throughput (req/s)
  - Response Time (mean, P95, P99)
  - Error rate

Wrapper untuk ApacheBench (ab) sesuai proposal, dengan output JSON
untuk comparative testing Baseline vs Enhanced WAF.

Penggunaan:
  python load_test.py --target http://localhost --requests 10000 --concurrency 100
=============================================================================
"""

import sys
import re
import json
import subprocess
import argparse
import time
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# APACHEBENCH WRAPPER
# ─────────────────────────────────────────────────────────────────────────────

def run_ab(url: str, n: int, c: int, extra_headers: dict | None = None) -> dict:
    """
    Jalankan ApacheBench dan parse hasilnya.

    Args:
        url:           URL target
        n:             Jumlah total request
        c:             Jumlah concurrent connections
        extra_headers: Header tambahan (dict)

    Returns:
        Dict hasil parsing ab output
    """
    cmd = ["ab", f"-n{n}", f"-c{c}", "-k", "-r"]

    # Header tambahan
    if extra_headers:
        for k, v in extra_headers.items():
            cmd += ["-H", f"{k}: {v}"]

    cmd.append(url)

    print(f"\n  Running: {' '.join(cmd[:6])} ... {url}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return parse_ab_output(result.stdout, result.returncode)
    except FileNotFoundError:
        print("  [!] ApacheBench (ab) tidak ditemukan. Install: apt install apache2-utils")
        return {"error": "ab not found"}
    except subprocess.TimeoutExpired:
        return {"error": "ab timeout"}


def parse_ab_output(output: str, returncode: int) -> dict:
    """Parse output teks ApacheBench ke dict."""
    metrics = {"ab_exit_code": returncode}

    patterns = {
        "requests_per_second":   r"Requests per second:\s+([\d.]+)",
        "time_per_request_mean": r"Time per request:\s+([\d.]+)\s+\[ms\] \(mean\)",
        "time_per_request_conn": r"Time per request:\s+([\d.]+)\s+\[ms\] \(mean, across all concurrent requests\)",
        "transfer_rate":         r"Transfer rate:\s+([\d.]+)",
        "total_requests":        r"Complete requests:\s+(\d+)",
        "failed_requests":       r"Failed requests:\s+(\d+)",
        "non_2xx_responses":     r"Non-2xx responses:\s+(\d+)",
        "total_transferred":     r"Total transferred:\s+(\d+)",
        "connect_ms_mean":       r"Connect:\s+\d+\s+(\d+)",
        "time_50pct":            r"50%\s+(\d+)",
        "time_66pct":            r"66%\s+(\d+)",
        "time_75pct":            r"75%\s+(\d+)",
        "time_80pct":            r"80%\s+(\d+)",
        "time_90pct":            r"90%\s+(\d+)",
        "time_95pct":            r"95%\s+(\d+)",
        "time_98pct":            r"98%\s+(\d+)",
        "time_99pct":            r"99%\s+(\d+)",
        "time_100pct":           r"100%\s+(\d+)",
        "test_duration_s":       r"Time taken for tests:\s+([\d.]+)\s+seconds",
    }

    for key, pattern in patterns.items():
        m = re.search(pattern, output)
        if m:
            try:
                metrics[key] = float(m.group(1))
            except ValueError:
                metrics[key] = m.group(1)

    metrics["raw_output"] = output[-2000:]  # Simpan 2000 char terakhir
    return metrics


# ─────────────────────────────────────────────────────────────────────────────
# TEST SCENARIOS
# ─────────────────────────────────────────────────────────────────────────────

def run_load_tests(target: str, n: int, c: int) -> dict:
    """
    Jalankan serangkaian load test sesuai skenario proposal TA.

    Skenario:
      1. Normal traffic (GET /)
      2. API endpoint (GET /api/products)
      3. Static assets (GET /static/img/logo.png)
      4. Mixed load (beberapa endpoint sekaligus)
    """
    base = target.rstrip("/")
    results = {}

    scenarios = [
        {
            "name":    "normal_homepage",
            "label":   "Normal Traffic (GET /)",
            "url":     f"{base}/",
            "headers": {
                "Referer":         f"{base}/",
                "Accept-Language": "id-ID",
                "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            },
        },
        {
            "name":    "api_endpoint",
            "label":   "API Endpoint (GET /api/products)",
            "url":     f"{base}/api/products",
            "headers": {
                "Referer":         f"{base}/shop",
                "Accept-Language": "id-ID",
                "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            },
        },
        {
            "name":    "static_assets",
            "label":   "Static Assets (GET /static/img/logo.png)",
            "url":     f"{base}/static/img/logo.png",
            "headers": {
                "Referer":         f"{base}/",
                "User-Agent":      "Mozilla/5.0",
                "Accept":          "image/webp,image/apng,*/*",
            },
        },
    ]

    for sc in scenarios:
        print(f"\n[*] Scenario: {sc['label']}")
        print(f"    n={n}, c={c}")
        res = run_ab(sc["url"], n, c, sc.get("headers"))
        results[sc["name"]] = {
            "label":  sc["label"],
            "url":    sc["url"],
            "n":      n,
            "c":      c,
            **res,
        }
        # Tunggu sebentar antar skenario
        time.sleep(2)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# PRINT & SAVE
# ─────────────────────────────────────────────────────────────────────────────

def print_load_results(results: dict):
    print("\n" + "="*70)
    print("HASIL LOAD TESTING — PERFORMA WAF")
    print("="*70)
    for name, r in results.items():
        if "error" in r:
            print(f"\n  [{name}] ERROR: {r['error']}")
            continue
        print(f"\n  Skenario : {r.get('label', name)}")
        print(f"  URL      : {r.get('url', '—')}")
        print(f"  Requests : {int(r.get('n', 0))} total, {int(r.get('c', 0))} concurrent")
        print(f"  ┌──────────────────────────────────────┐")
        print(f"  │ Throughput        : {r.get('requests_per_second', 0):>8.2f} req/s  │")
        print(f"  │ Response Time Mean: {r.get('time_per_request_mean', 0):>8.2f} ms     │")
        print(f"  │ Response Time P95 : {r.get('time_95pct', 0):>8.1f} ms     │")
        print(f"  │ Response Time P99 : {r.get('time_99pct', 0):>8.1f} ms     │")
        print(f"  │ Failed Requests   : {int(r.get('failed_requests', 0)):>8}         │")
        print(f"  │ Non-2xx Responses : {int(r.get('non_2xx_responses', 0)):>8}         │")
        print(f"  └──────────────────────────────────────┘")
    print("="*70)


def main():
    parser = argparse.ArgumentParser(
        description="Load Testing WAF — Taqiya Nabilla Nathania Afnani, PSSN 2026"
    )
    parser.add_argument("--target",      default="http://localhost",
                        help="Target WAF URL")
    parser.add_argument("--requests",    type=int, default=10000,
                        help="Jumlah total request (default: 10000)")
    parser.add_argument("--concurrency", type=int, default=100,
                        help="Jumlah concurrent connections (default: 100)")
    parser.add_argument("--output",      default="hasil_load_test.json",
                        help="Output file JSON")
    parser.add_argument("--label",       default="enhanced",
                        choices=["baseline", "enhanced"],
                        help="Label konfigurasi WAF (untuk comparative testing)")
    args = parser.parse_args()

    print("""
╔══════════════════════════════════════════════════════════════════╗
║           Load Testing Script — Fase 4 Evaluasi Performa        ║
║           Taqiya Nabilla Nathania Afnani — PSSN 2026            ║
╚══════════════════════════════════════════════════════════════════╝
""")
    print(f"Target     : {args.target}")
    print(f"Requests   : {args.requests}")
    print(f"Concurrency: {args.concurrency}")
    print(f"Label WAF  : {args.label}")
    print(f"Waktu mulai: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    results = run_load_tests(args.target, args.requests, args.concurrency)
    print_load_results(results)

    output = {
        "metadata": {
            "target":       args.target,
            "requests":     args.requests,
            "concurrency":  args.concurrency,
            "waf_label":    args.label,
            "timestamp":    datetime.now().isoformat(),
            "researcher":   "Taqiya Nabilla Nathania Afnani — PSSN 2026",
        },
        "scenarios": results,
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\n[+] Hasil disimpan ke: {args.output}")
    print(f"[+] Selesai: {datetime.now().strftime('%H:%M:%S')}")


if __name__ == "__main__":
    main()

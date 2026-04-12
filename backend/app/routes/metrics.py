"""
Metrics Routes — ABR, FPR, FNR, Throughput per Site
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import func
from datetime import datetime, timedelta, timezone
from app.models import Site, AttackLog, User
from app import db
import statistics

metrics_bp = Blueprint("metrics", __name__)


def _current_user():
    return User.query.get(get_jwt_identity())


def _calculate_site_metrics(site_id: str, days: int = 1) -> dict:
    """Hitung metrik WAF (ABR, FPR, FNR) dari AttackLog database."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    logs  = AttackLog.query.filter(
        AttackLog.site_id == site_id,
        AttackLog.timestamp >= since
    ).all()

    if not logs:
        return {
            "total_requests": 0, "attacks_total": 0,
            "attacks_blocked": 0, "attacks_passed": 0,
            "legit_blocked": 0, "legit_passed": 0,
            "abr": 0.0, "fpr": 0.0, "fnr": 0.0,
            "throughput": 0.0,
            "rt_mean": 0.0, "rt_p95": 0.0, "rt_p99": 0.0,
            "tag_distribution": {}, "hourly_blocks": {},
        }

    attack_actions = {"blocked", "challenged"}
    attack_types   = {"SQLi", "XSS", "LFI", "SSRF", "AntiScraping",
                      "Hotlinking", "RefererBypass", "WAF-BLOCK"}

    attacks_total   = sum(1 for l in logs if l.attack_type in attack_types)
    attacks_blocked = sum(1 for l in logs if l.attack_type in attack_types and l.action == "blocked")
    attacks_passed  = attacks_total - attacks_blocked
    legit_total     = sum(1 for l in logs if l.attack_type not in attack_types)
    legit_blocked   = sum(1 for l in logs if l.attack_type not in attack_types and l.action == "blocked")
    legit_passed    = legit_total - legit_blocked

    abr = (attacks_blocked / attacks_total * 100) if attacks_total > 0 else 0.0
    fpr = (legit_blocked  / legit_total    * 100) if legit_total   > 0 else 0.0
    fnr = (attacks_passed / attacks_total  * 100) if attacks_total > 0 else 0.0

    # Response times
    rts = [l.response_time_ms for l in logs if l.response_time_ms > 0]
    if rts:
        rts_sorted = sorted(rts)
        rt_mean = statistics.mean(rts)
        rt_p95  = rts_sorted[int(len(rts_sorted) * 0.95)]
        rt_p99  = rts_sorted[int(len(rts_sorted) * 0.99)]
    else:
        rt_mean = rt_p95 = rt_p99 = 0.0

    # Tag distribution
    from collections import Counter
    tag_dist = dict(Counter(l.attack_type for l in logs if l.attack_type and l.action == "blocked"))

    # Hourly blocks
    hourly = {}
    for l in logs:
        if l.action == "blocked":
            hour = l.timestamp.strftime("%H:00")
            hourly[hour] = hourly.get(hour, 0) + 1

    # Throughput (req/s over window)
    window_s = days * 86400
    throughput = len(logs) / window_s if window_s > 0 else 0

    return {
        "total_requests":  len(logs),
        "attacks_total":   attacks_total,
        "attacks_blocked": attacks_blocked,
        "attacks_passed":  attacks_passed,
        "legit_blocked":   legit_blocked,
        "legit_passed":    legit_passed,
        "abr":  round(abr,  2),
        "fpr":  round(fpr,  2),
        "fnr":  round(fnr,  2),
        "throughput": round(throughput, 4),
        "rt_mean": round(rt_mean, 2),
        "rt_p95":  round(rt_p95,  2),
        "rt_p99":  round(rt_p99,  2),
        "tag_distribution": tag_dist,
        "hourly_blocks":    dict(sorted(hourly.items())),
    }


@metrics_bp.route("/overview", methods=["GET"])
@jwt_required()
def overview():
    """Ringkasan metrik semua site milik user."""
    user  = _current_user()
    sites = Site.query.filter_by(user_id=user.id).all()

    total_blocked = 0
    total_attacks = 0
    site_summaries = []

    for site in sites:
        m = _calculate_site_metrics(site.id, days=1)
        total_blocked += m["attacks_blocked"]
        total_attacks += m["attacks_total"]
        site_summaries.append({
            "site_id":   site.id,
            "domain":    site.domain,
            "name":      site.name,
            "waf_enabled": site.waf_enabled,
            **{k: m[k] for k in ["abr", "fpr", "fnr", "attacks_blocked", "total_requests"]},
        })

    overall_abr = (total_blocked / total_attacks * 100) if total_attacks > 0 else 0.0

    return jsonify({
        "user_id":      user.id,
        "total_sites":  len(sites),
        "total_blocked_24h": total_blocked,
        "overall_abr":  round(overall_abr, 2),
        "sites":        site_summaries,
    }), 200


@metrics_bp.route("/site/<site_id>", methods=["GET"])
@jwt_required()
def site_metrics(site_id):
    """Metrik detail satu site."""
    user = _current_user()
    site = Site.query.filter_by(id=site_id, user_id=user.id).first()
    if not site:
        return jsonify({"error": "Site tidak ditemukan"}), 404

    days = int(request.args.get("days", 1))
    m    = _calculate_site_metrics(site_id, days=days)
    return jsonify({"site_id": site_id, "domain": site.domain, "days": days, "metrics": m}), 200


@metrics_bp.route("/site/<site_id>/ingest", methods=["POST"])
@jwt_required()
def ingest_log(site_id):
    """
    Endpoint untuk ingest log dari ModSecurity ke database.
    Dipanggil oleh log parser script, bukan user langsung.
    """
    user = _current_user()
    site = Site.query.filter_by(id=site_id, user_id=user.id).first()
    if not site:
        return jsonify({"error": "Site tidak ditemukan"}), 404

    entries = request.get_json() or []
    if isinstance(entries, dict):
        entries = [entries]

    created = 0
    for entry in entries[:100]:  # Max 100 per request
        log = AttackLog(
            site_id=site_id,
            client_ip=entry.get("client_ip"),
            method=entry.get("method"),
            uri=entry.get("uri"),
            referer=entry.get("referer"),
            user_agent=entry.get("user_agent"),
            attack_type=entry.get("attack_type"),
            severity=entry.get("severity", "medium"),
            action=entry.get("action", "blocked"),
            anomaly_score=entry.get("anomaly_score", 0),
            rule_id=entry.get("rule_id"),
            message=entry.get("message"),
            status_code=entry.get("status_code", 403),
            response_time_ms=entry.get("response_time_ms", 0),
        )
        db.session.add(log)
        created += 1

    db.session.commit()
    return jsonify({"message": f"{created} log berhasil diingest"}), 201


@metrics_bp.route("/site/<site_id>/demo-attack", methods=["POST"])
@jwt_required()
def demo_attack(site_id):
    """Simulate beberapa log serangan untuk demo/testing."""
    import random
    from datetime import timedelta

    user = _current_user()
    site = Site.query.filter_by(id=site_id, user_id=user.id).first()
    if not site:
        return jsonify({"error": "Site tidak ditemukan"}), 404

    demo_attacks = [
        {"attack_type": "SQLi",          "severity": "critical", "uri": "/api/search", "method": "GET",
         "message": "SQL Injection attempt detected", "rule_id": "942100", "anomaly_score": 15},
        {"attack_type": "XSS",           "severity": "critical", "uri": "/comments",   "method": "POST",
         "message": "XSS payload in request body",   "rule_id": "941100", "anomaly_score": 13},
        {"attack_type": "AntiScraping",  "severity": "high",     "uri": "/api/products","method": "GET",
         "message": "Known scraping bot detected",   "rule_id": "1001001","anomaly_score": 8},
        {"attack_type": "Hotlinking",    "severity": "medium",   "uri": "/static/img/logo.png","method": "GET",
         "message": "Hotlinking from external domain","rule_id": "1002001","anomaly_score": 5},
        {"attack_type": "RefererBypass", "severity": "high",     "uri": "/api/users",  "method": "GET",
         "message": "HTTP Referer bypass detected",  "rule_id": "1000003","anomaly_score": 10},
        {"attack_type": "LFI",           "severity": "high",     "uri": "/files",      "method": "GET",
         "message": "Path traversal attempt",        "rule_id": "930100", "anomaly_score": 9},
    ]
    ips = ["203.0.113.47", "198.51.100.22", "192.0.2.189", "45.33.32.156"]

    count = int(request.get_json().get("count", 20)) if request.is_json else 20
    count = min(count, 100)

    for i in range(count):
        atk = random.choice(demo_attacks)
        ts  = datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 1440))
        log = AttackLog(
            site_id=site_id,
            client_ip=random.choice(ips),
            method=atk["method"],
            uri=atk["uri"],
            referer=random.choice(["http://evil.com/", "", "http://competitor.com/"]),
            user_agent=random.choice(["Scrapy/2.11", "python-requests/2.31", "Mozilla/5.0"]),
            attack_type=atk["attack_type"],
            severity=atk["severity"],
            action=random.choice(["blocked", "blocked", "blocked", "passed"]),
            anomaly_score=atk["anomaly_score"] + random.randint(-2, 5),
            rule_id=atk["rule_id"],
            message=atk["message"],
            status_code=random.choice([403, 403, 403, 200]),
            response_time_ms=round(random.uniform(1, 50), 2),
            timestamp=ts,
        )
        db.session.add(log)

    db.session.commit()
    return jsonify({"message": f"{count} demo log serangan berhasil dibuat untuk {site.domain}"}), 201

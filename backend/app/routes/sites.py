"""
Sites Routes — Manajemen Origin Server per User
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models import Site, User, AttackLog
from app.services.nginx_generator import write_site_config, remove_site_config, reload_nginx
import re

sites_bp = Blueprint("sites", __name__)

DOMAIN_RE = re.compile(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$")


def _validate_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain.lower()))


def _current_user() -> User | None:
    uid = get_jwt_identity()
    return User.query.get(uid)


# ─── List semua site milik user ───────────────────────────────────────────────
@sites_bp.route("/", methods=["GET"])
@jwt_required()
def list_sites():
    user = _current_user()
    if not user:
        return jsonify({"error": "User tidak ditemukan"}), 404
    sites = Site.query.filter_by(user_id=user.id).order_by(Site.created_at.desc()).all()
    return jsonify({"sites": [s.to_dict() for s in sites], "total": len(sites)}), 200


# ─── Tambah site baru ─────────────────────────────────────────────────────────
@sites_bp.route("/", methods=["POST"])
@jwt_required()
def create_site():
    user = _current_user()
    if not user:
        return jsonify({"error": "User tidak ditemukan"}), 404

    data = request.get_json() or {}

    # Validasi wajib
    for field in ["name", "domain", "origin_url"]:
        if not data.get(field, "").strip():
            return jsonify({"error": f"Field '{field}' wajib diisi"}), 400

    domain = data["domain"].strip().lower().removeprefix("https://").removeprefix("http://").rstrip("/")
    if not _validate_domain(domain):
        return jsonify({"error": "Format domain tidak valid (contoh: myapp.com)"}), 400

    # Cek domain sudah terdaftar
    if Site.query.filter_by(domain=domain).first():
        return jsonify({"error": f"Domain '{domain}' sudah terdaftar di sistem"}), 409

    # Validasi origin_url
    origin_url = data["origin_url"].strip()
    if not origin_url.startswith(("http://", "https://")):
        origin_url = "http://" + origin_url

    # Buat site
    site = Site(
        user_id=user.id,
        name=data["name"].strip(),
        domain=domain,
        origin_url=origin_url,
        description=data.get("description", "").strip(),
        waf_enabled=data.get("waf_enabled", True),
        ssl_enabled=data.get("ssl_enabled", False),
        paranoia_level=min(max(int(data.get("paranoia_level", 1)), 1), 4),
        anomaly_threshold=min(max(int(data.get("anomaly_threshold", 5)), 1), 20),
        block_scraping=data.get("block_scraping", True),
        block_hotlinking=data.get("block_hotlinking", True),
        block_referer_bypass=data.get("block_referer_bypass", True),
        rate_limit_rpm=min(max(int(data.get("rate_limit_rpm", 100)), 1), 10000),
    )
    db.session.add(site)
    db.session.flush()  # Dapatkan ID sebelum commit

    # Generate konfigurasi Nginx + ModSecurity
    try:
        conf_paths = write_site_config(site)
        site.nginx_conf_file  = conf_paths["nginx_conf"]
        site.modsec_conf_file = conf_paths["modsec_conf"]
    except Exception as e:
        current_app.logger.warning(f"Gagal write config: {e}")

    db.session.commit()

    # Reload Nginx
    reload_nginx()

    return jsonify({
        "message": f"Site '{site.name}' berhasil ditambahkan. WAF aktif untuk {domain}.",
        "site": site.to_dict(),
    }), 201


# ─── Detail satu site ─────────────────────────────────────────────────────────
@sites_bp.route("/<site_id>", methods=["GET"])
@jwt_required()
def get_site(site_id):
    user = _current_user()
    site = Site.query.filter_by(id=site_id, user_id=user.id).first()
    if not site:
        return jsonify({"error": "Site tidak ditemukan"}), 404
    return jsonify({"site": site.to_dict()}), 200


# ─── Update site ──────────────────────────────────────────────────────────────
@sites_bp.route("/<site_id>", methods=["PUT"])
@jwt_required()
def update_site(site_id):
    user = _current_user()
    site = Site.query.filter_by(id=site_id, user_id=user.id).first()
    if not site:
        return jsonify({"error": "Site tidak ditemukan"}), 404

    data = request.get_json() or {}
    updatable = ["name", "description", "origin_url", "waf_enabled", "ssl_enabled",
                 "paranoia_level", "anomaly_threshold", "block_scraping",
                 "block_hotlinking", "block_referer_bypass", "rate_limit_rpm"]

    for field in updatable:
        if field in data:
            val = data[field]
            if field in ["paranoia_level"]:
                val = min(max(int(val), 1), 4)
            elif field in ["anomaly_threshold"]:
                val = min(max(int(val), 1), 20)
            elif field in ["rate_limit_rpm"]:
                val = min(max(int(val), 1), 10000)
            setattr(site, field, val)

    # Re-generate konfigurasi
    try:
        conf_paths = write_site_config(site)
        site.nginx_conf_file  = conf_paths["nginx_conf"]
        site.modsec_conf_file = conf_paths["modsec_conf"]
    except Exception as e:
        current_app.logger.warning(f"Gagal write config: {e}")

    db.session.commit()
    reload_nginx()

    return jsonify({"message": "Site berhasil diperbarui", "site": site.to_dict()}), 200


# ─── Hapus site ───────────────────────────────────────────────────────────────
@sites_bp.route("/<site_id>", methods=["DELETE"])
@jwt_required()
def delete_site(site_id):
    user = _current_user()
    site = Site.query.filter_by(id=site_id, user_id=user.id).first()
    if not site:
        return jsonify({"error": "Site tidak ditemukan"}), 404

    name = site.name
    remove_site_config(site)
    db.session.delete(site)
    db.session.commit()
    reload_nginx()

    return jsonify({"message": f"Site '{name}' berhasil dihapus"}), 200


# ─── Toggle WAF aktif/nonaktif ────────────────────────────────────────────────
@sites_bp.route("/<site_id>/toggle-waf", methods=["POST"])
@jwt_required()
def toggle_waf(site_id):
    user = _current_user()
    site = Site.query.filter_by(id=site_id, user_id=user.id).first()
    if not site:
        return jsonify({"error": "Site tidak ditemukan"}), 404

    site.waf_enabled = not site.waf_enabled
    try:
        write_site_config(site)
    except Exception:
        pass
    db.session.commit()
    reload_nginx()

    status = "diaktifkan" if site.waf_enabled else "dinonaktifkan"
    return jsonify({"message": f"WAF {status} untuk {site.domain}", "waf_enabled": site.waf_enabled}), 200


# ─── Logs per site ────────────────────────────────────────────────────────────
@sites_bp.route("/<site_id>/logs", methods=["GET"])
@jwt_required()
def site_logs(site_id):
    user = _current_user()
    site = Site.query.filter_by(id=site_id, user_id=user.id).first()
    if not site:
        return jsonify({"error": "Site tidak ditemukan"}), 404

    limit      = min(int(request.args.get("limit", 50)), 500)
    attack_type= request.args.get("type", None)

    query = AttackLog.query.filter_by(site_id=site_id)
    if attack_type:
        query = query.filter_by(attack_type=attack_type)
    logs = query.order_by(AttackLog.timestamp.desc()).limit(limit).all()

    return jsonify({"logs": [l.to_dict() for l in logs], "total": len(logs)}), 200

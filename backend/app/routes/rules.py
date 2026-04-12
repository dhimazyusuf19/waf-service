"""
Rules Routes — Manajemen Custom WAF Rules per Site
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import Site, User

rules_bp = Blueprint("rules", __name__)


def _current_user():
    return User.query.get(get_jwt_identity())


@rules_bp.route("/site/<site_id>", methods=["GET"])
@jwt_required()
def get_site_rules(site_id):
    """Ambil konfigurasi WAF rules untuk satu site."""
    user = _current_user()
    site = Site.query.filter_by(id=site_id, user_id=user.id).first()
    if not site:
        return jsonify({"error": "Site tidak ditemukan"}), 404

    return jsonify({
        "site_id":   site_id,
        "domain":    site.domain,
        "rules": {
            "waf_enabled":          site.waf_enabled,
            "paranoia_level":       site.paranoia_level,
            "anomaly_threshold":    site.anomaly_threshold,
            "block_scraping":       site.block_scraping,
            "block_hotlinking":     site.block_hotlinking,
            "block_referer_bypass": site.block_referer_bypass,
            "rate_limit_rpm":       site.rate_limit_rpm,
        }
    }), 200


@rules_bp.route("/site/<site_id>", methods=["PUT"])
@jwt_required()
def update_site_rules(site_id):
    """Update konfigurasi WAF rules untuk satu site."""
    from app import db
    from app.services.nginx_generator import write_site_config, reload_nginx

    user = _current_user()
    site = Site.query.filter_by(id=site_id, user_id=user.id).first()
    if not site:
        return jsonify({"error": "Site tidak ditemukan"}), 404

    data = request.get_json() or {}
    updatable = ["waf_enabled", "paranoia_level", "anomaly_threshold",
                 "block_scraping", "block_hotlinking", "block_referer_bypass", "rate_limit_rpm"]

    for field in updatable:
        if field in data:
            val = data[field]
            if field == "paranoia_level":
                val = min(max(int(val), 1), 4)
            elif field == "anomaly_threshold":
                val = min(max(int(val), 1), 20)
            elif field == "rate_limit_rpm":
                val = min(max(int(val), 1), 10000)
            setattr(site, field, val)

    try:
        write_site_config(site)
    except Exception:
        pass
    db.session.commit()
    reload_nginx()

    return jsonify({"message": "WAF rules berhasil diperbarui", "rules": {
        "waf_enabled":          site.waf_enabled,
        "paranoia_level":       site.paranoia_level,
        "anomaly_threshold":    site.anomaly_threshold,
        "block_scraping":       site.block_scraping,
        "block_hotlinking":     site.block_hotlinking,
        "block_referer_bypass": site.block_referer_bypass,
        "rate_limit_rpm":       site.rate_limit_rpm,
    }}), 200

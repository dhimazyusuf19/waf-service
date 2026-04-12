"""
Nginx Config Generator
Membuat konfigurasi Nginx per-site secara dinamis berdasarkan data Site dari database.
"""

import os
import subprocess
from pathlib import Path
from flask import current_app
from app.models import Site


NGINX_SITE_TEMPLATE = """\
# ─────────────────────────────────────────────────────────────────────────────
# WAF Site Config: {domain}
# Site ID: {site_id}
# Owner: {user_id}
# Generated: {generated_at}
# ─────────────────────────────────────────────────────────────────────────────

# Rate limiting zone per-site
limit_req_zone $binary_remote_addr zone=rate_{site_id_short}:10m rate={rate_limit}r/m;

# Bot User-Agent detection
map $http_user_agent $is_bot_{site_id_short} {{
    default 0;
    "~*scrapy|python-requests|curl|wget|go-http-client|libwww-perl|selenium|phantomjs" 1;
    "" 1;
}}

# Referer validation
map $http_referer $referer_ok_{site_id_short} {{
    default 0;
    "~*^https?://(www\\.)?{domain_escaped}" 1;
    "~*^https?://localhost" 1;
    "" {allow_empty_referer};
}}

upstream origin_{site_id_short} {{
    server {origin_host}:{origin_port};
    keepalive 32;
}}

server {{
    listen 80;
    server_name {domain} www.{domain};
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl http2;
    server_name {domain} www.{domain};

    # SSL
    ssl_certificate     /etc/nginx/ssl/default.crt;
    ssl_certificate_key /etc/nginx/ssl/default.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # ModSecurity per-site
    modsecurity {modsec_status};
    modsecurity_rules_file /etc/nginx/modsecurity/sites/{site_id}.conf;

    # ─── Anti-Scraping: blokir bot ─────────────────────────────────────────
    {scraping_block}

    # ─── Hotlink Protection ────────────────────────────────────────────────
    location ~* \\.(jpg|jpeg|png|gif|webp|mp4|pdf|zip|svg|ico)$ {{
        {hotlink_check}
        limit_req zone=rate_{site_id_short} burst=50 nodelay;
        proxy_pass http://origin_{site_id_short};
        include /etc/nginx/conf.d/proxy_params.conf;
    }}

    # ─── API dengan Referer check ──────────────────────────────────────────
    location /api/ {{
        {referer_check}
        limit_req zone=rate_{site_id_short} burst=20 nodelay;
        proxy_pass http://origin_{site_id_short};
        include /etc/nginx/conf.d/proxy_params.conf;
    }}

    # ─── General ───────────────────────────────────────────────────────────
    location / {{
        limit_req zone=rate_{site_id_short} burst=50 nodelay;
        proxy_pass http://origin_{site_id_short};
        include /etc/nginx/conf.d/proxy_params.conf;
    }}

    access_log /var/log/nginx/{site_id}_access.log waf_detailed;
    error_log  /var/log/nginx/{site_id}_error.log warn;
}}
"""

MODSEC_SITE_TEMPLATE = """\
# ModSecurity config untuk site: {domain}
# Site ID: {site_id}

Include /etc/nginx/modsecurity/modsecurity.conf
Include /etc/nginx/modsecurity/crs-setup/crs-setup.conf
Include /etc/nginx/modsecurity/crs/rules/REQUEST-901-INITIALIZATION.conf
Include /etc/nginx/modsecurity/crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf
Include /etc/nginx/modsecurity/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
Include /etc/nginx/modsecurity/crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf
Include /etc/nginx/modsecurity/crs/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf
Include /etc/nginx/modsecurity/crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf
Include /etc/nginx/modsecurity/crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf
Include /etc/nginx/modsecurity/crs/rules/RESPONSE-980-CORRELATION.conf

# Custom rules
Include /etc/nginx/modsecurity/custom-rules/1000-referer-bypass.conf
Include /etc/nginx/modsecurity/custom-rules/1001-anti-scraping.conf
Include /etc/nginx/modsecurity/custom-rules/1002-anti-hotlinking.conf
Include /etc/nginx/modsecurity/custom-rules/1003-anomaly-scoring.conf
Include /etc/nginx/modsecurity/custom-rules/1004-whitelist.conf

# Per-site overrides
SecAction \\
    "id:9{id_suffix}001,\\
    phase:1,nolog,pass,\\
    setvar:tx.inbound_anomaly_score_threshold={threshold},\\
    setvar:tx.paranoia_level={paranoia}"

SecAction \\
    "id:9{id_suffix}002,\\
    phase:1,nolog,pass,\\
    setvar:tx.allowed_domains='{domain}|www.{domain}'"
"""


def _parse_origin_url(origin_url: str):
    """Parse origin URL menjadi host dan port."""
    url = origin_url.rstrip("/")
    if "://" in url:
        url = url.split("://", 1)[1]
    if ":" in url:
        parts = url.rsplit(":", 1)
        return parts[0], int(parts[1])
    return url, 80


def generate_nginx_config(site: Site) -> str:
    """Generate isi file konfigurasi Nginx untuk satu site."""
    host, port = _parse_origin_url(site.origin_url)
    short_id   = site.id.replace("-", "")[:12]
    domain_esc = site.domain.replace(".", "\\.")

    # Scraping block snippet
    scraping_block = ""
    if site.block_scraping:
        scraping_block = f"if ($is_bot_{short_id} = 1) {{ return 403 \"Automated request blocked.\"; }}"

    # Hotlink check snippet
    hotlink_check = ""
    if site.block_hotlinking:
        hotlink_check = (
            f"valid_referers none blocked server_names {site.domain} www.{site.domain};\n"
            f"        if ($invalid_referer) {{ return 403 \"Hotlinking not allowed.\"; }}"
        )

    # Referer check snippet
    referer_check = ""
    if site.block_referer_bypass:
        referer_check = (
            f"if ($referer_ok_{short_id} = 0) {{ return 403 \"Invalid HTTP Referer.\"; }}"
        )

    from datetime import datetime
    return NGINX_SITE_TEMPLATE.format(
        domain=site.domain,
        domain_escaped=domain_esc,
        site_id=site.id,
        site_id_short=short_id,
        user_id=site.user_id,
        generated_at=datetime.utcnow().isoformat(),
        origin_host=host,
        origin_port=port,
        rate_limit=site.rate_limit_rpm,
        modsec_status="on" if site.waf_enabled else "off",
        scraping_block=scraping_block,
        hotlink_check=hotlink_check,
        referer_check=referer_check,
        allow_empty_referer="1",
    )


def generate_modsec_config(site: Site) -> str:
    """Generate isi file konfigurasi ModSecurity untuk satu site."""
    short_num = str(abs(hash(site.id)))[:3]
    return MODSEC_SITE_TEMPLATE.format(
        domain=site.domain,
        site_id=site.id,
        threshold=site.anomaly_threshold,
        paranoia=site.paranoia_level,
        id_suffix=short_num,
    )


def write_site_config(site: Site) -> dict:
    """Tulis file konfigurasi Nginx dan ModSecurity untuk site ke disk."""
    nginx_dir   = Path(current_app.config["NGINX_CONF_DIR"])
    modsec_dir  = Path(current_app.config["MODSEC_RULES_DIR"])

    nginx_dir.mkdir(parents=True, exist_ok=True)
    modsec_dir.mkdir(parents=True, exist_ok=True)

    nginx_file  = nginx_dir  / f"site_{site.id}.conf"
    modsec_file = modsec_dir / f"{site.id}.conf"

    nginx_file.write_text(generate_nginx_config(site))
    modsec_file.write_text(generate_modsec_config(site))

    return {
        "nginx_conf":  str(nginx_file),
        "modsec_conf": str(modsec_file),
    }


def remove_site_config(site: Site):
    """Hapus file konfigurasi site dari disk."""
    nginx_dir  = Path(current_app.config["NGINX_CONF_DIR"])
    modsec_dir = Path(current_app.config["MODSEC_RULES_DIR"])

    for f in [nginx_dir / f"site_{site.id}.conf",
              modsec_dir / f"{site.id}.conf"]:
        try:
            f.unlink(missing_ok=True)
        except Exception:
            pass


def reload_nginx() -> bool:
    """Reload Nginx tanpa downtime (nginx -s reload)."""
    try:
        result = subprocess.run(
            ["nginx", "-s", "reload"],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        # Dalam dev mode tanpa Nginx, skip
        return True

"""
WAF SaaS — Backend API
Taqiya Nabilla Nathania Afnani — PSSN 2026

Flask application factory dengan:
- JWT Authentication (register/login)
- Multi-tenant origin server management
- Dynamic Nginx config generation
- Real-time log parsing & metrics (ABR/FPR/FNR)
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import timedelta
import os

db = SQLAlchemy()
jwt = JWTManager()
bcrypt = Bcrypt()


def create_app():
    app = Flask(__name__)

    # ─── Configuration ─────────────────────────────────────────────────────
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///waf_saas.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "jwt-dev-secret")
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

    app.config["NGINX_CONF_DIR"]    = os.environ.get("NGINX_CONF_DIR", "/etc/nginx/conf.d")
    app.config["NGINX_TEMPLATE_DIR"]= os.environ.get("NGINX_TEMPLATE_DIR", "nginx_templates")
    app.config["MODSEC_RULES_DIR"]  = os.environ.get("MODSEC_RULES_DIR", "/etc/nginx/modsecurity/sites")
    app.config["LOG_DIR"]           = os.environ.get("LOG_DIR", "/var/log/modsecurity")
    app.config["NGINX_LOG_DIR"]     = os.environ.get("NGINX_LOG_DIR", "/var/log/nginx")

    # ─── Extensions ────────────────────────────────────────────────────────
    db.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)

    _default_origins = "http://localhost:3000,http://localhost:80,https://waf.local,http://waf.local"
    _cors_origins = [
        o.strip()
        for o in os.environ.get("CORS_ORIGINS", _default_origins).split(",")
        if o.strip()
    ]
    CORS(app, origins=_cors_origins, supports_credentials=True)

    # ─── Register Blueprints ───────────────────────────────────────────────
    from app.routes.auth    import auth_bp
    from app.routes.sites   import sites_bp
    from app.routes.metrics import metrics_bp
    from app.routes.rules   import rules_bp

    app.register_blueprint(auth_bp,    url_prefix="/api/auth")
    app.register_blueprint(sites_bp,   url_prefix="/api/sites")
    app.register_blueprint(metrics_bp, url_prefix="/api/metrics")
    app.register_blueprint(rules_bp,   url_prefix="/api/rules")

    # ─── Health check ──────────────────────────────────────────────────────
    @app.route("/health")
    @app.route("/api/health")
    def health():
        return {"status": "ok", "service": "WAF SaaS API", "version": "1.0.0"}

    # ─── Create tables ─────────────────────────────────────────────────────
    with app.app_context():
        db.create_all()

    return app

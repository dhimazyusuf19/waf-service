"""
Database Models — WAF SaaS
"""

from app import db
from datetime import datetime, timezone
import uuid


def gen_uuid():
    return str(uuid.uuid4())


class User(db.Model):
    """User/Admin account."""
    __tablename__ = "users"

    id         = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    email      = db.Column(db.String(255), unique=True, nullable=False, index=True)
    username   = db.Column(db.String(80),  unique=True, nullable=False)
    password   = db.Column(db.String(255), nullable=False)
    full_name  = db.Column(db.String(150), nullable=True)
    role       = db.Column(db.String(20),  default="user")   # user | admin
    is_active  = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    sites = db.relationship("Site", back_populates="owner", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id":         self.id,
            "email":      self.email,
            "username":   self.username,
            "full_name":  self.full_name,
            "role":       self.role,
            "is_active":  self.is_active,
            "created_at": self.created_at.isoformat(),
            "site_count": len(self.sites),
        }


class Site(db.Model):
    """
    Origin server/website yang didaftarkan user untuk dilindungi WAF.
    Satu user bisa punya banyak site (multi-tenant).
    """
    __tablename__ = "sites"

    id           = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    user_id      = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)

    # Identitas site
    name         = db.Column(db.String(100), nullable=False)          # Nama tampilan
    domain       = db.Column(db.String(255), nullable=False, unique=True)  # domain.com
    origin_url   = db.Column(db.String(500), nullable=False)          # http://192.168.1.10:8080
    description  = db.Column(db.Text, nullable=True)

    # Status
    is_active    = db.Column(db.Boolean, default=True)
    waf_enabled  = db.Column(db.Boolean, default=True)
    ssl_enabled  = db.Column(db.Boolean, default=False)

    # WAF settings per-site
    paranoia_level      = db.Column(db.Integer, default=1)   # 1-4
    anomaly_threshold   = db.Column(db.Integer, default=5)   # score threshold
    block_scraping      = db.Column(db.Boolean, default=True)
    block_hotlinking    = db.Column(db.Boolean, default=True)
    block_referer_bypass= db.Column(db.Boolean, default=True)
    rate_limit_rpm      = db.Column(db.Integer, default=100)  # request per menit

    # Nginx config file path (generated)
    nginx_conf_file = db.Column(db.String(255), nullable=True)
    modsec_conf_file= db.Column(db.String(255), nullable=True)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    owner  = db.relationship("User", back_populates="sites")
    logs   = db.relationship("AttackLog", back_populates="site", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id":                  self.id,
            "user_id":             self.user_id,
            "name":                self.name,
            "domain":              self.domain,
            "origin_url":          self.origin_url,
            "description":         self.description,
            "is_active":           self.is_active,
            "waf_enabled":         self.waf_enabled,
            "ssl_enabled":         self.ssl_enabled,
            "paranoia_level":      self.paranoia_level,
            "anomaly_threshold":   self.anomaly_threshold,
            "block_scraping":      self.block_scraping,
            "block_hotlinking":    self.block_hotlinking,
            "block_referer_bypass":self.block_referer_bypass,
            "rate_limit_rpm":      self.rate_limit_rpm,
            "created_at":          self.created_at.isoformat(),
            "updated_at":          self.updated_at.isoformat(),
            "log_count":           len(self.logs),
        }


class AttackLog(db.Model):
    """Log serangan yang dideteksi WAF per site."""
    __tablename__ = "attack_logs"

    id          = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    site_id     = db.Column(db.String(36), db.ForeignKey("sites.id"), nullable=False)

    # Request info
    client_ip   = db.Column(db.String(45),  nullable=True)
    method      = db.Column(db.String(10),  nullable=True)
    uri         = db.Column(db.String(500), nullable=True)
    referer     = db.Column(db.String(500), nullable=True)
    user_agent  = db.Column(db.String(500), nullable=True)

    # Detection info
    attack_type = db.Column(db.String(50),  nullable=True)   # SQLi, XSS, Scraping, ...
    severity    = db.Column(db.String(20),  default="medium") # low, medium, high, critical
    action      = db.Column(db.String(20),  default="blocked") # blocked, passed
    anomaly_score = db.Column(db.Integer,   default=0)
    rule_id     = db.Column(db.String(20),  nullable=True)
    message     = db.Column(db.Text,        nullable=True)

    # Response info
    status_code = db.Column(db.Integer,     default=403)
    response_time_ms = db.Column(db.Float,  default=0)

    timestamp   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # Relationships
    site = db.relationship("Site", back_populates="logs")

    def to_dict(self):
        return {
            "id":           self.id,
            "site_id":      self.site_id,
            "client_ip":    self.client_ip,
            "method":       self.method,
            "uri":          self.uri,
            "referer":      self.referer,
            "user_agent":   self.user_agent,
            "attack_type":  self.attack_type,
            "severity":     self.severity,
            "action":       self.action,
            "anomaly_score":self.anomaly_score,
            "rule_id":      self.rule_id,
            "message":      self.message,
            "status_code":  self.status_code,
            "response_time_ms": self.response_time_ms,
            "timestamp":    self.timestamp.isoformat(),
        }

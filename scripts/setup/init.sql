-- WAF SaaS Database Initialization
-- Taqiya Nabilla Nathania Afnani — PSSN 2026

-- Tables are created by SQLAlchemy on startup via db.create_all()
-- This script runs first for any manual setup needed

-- Enable UUID extension (PostgreSQL)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE waf_saas TO waf_admin;

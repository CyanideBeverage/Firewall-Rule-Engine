"""
Configuration settings for the Firewall Rule Engine application.
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Secret key used by Flask to cryptographically sign session cookies.
    # In production, load this from an environment variable.
    SECRET_KEY = os.environ.get("FIREWALL_SECRET_KEY", "dev-firewall-rule-engine-secret-key-2026")

    # SQLite database file path
    DATABASE_PATH = os.path.join(BASE_DIR, "firewall.db")

    # Session cookie security settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Default administrator account created on first database initialization
    DEFAULT_ADMIN_USERNAME = "admin"
    DEFAULT_ADMIN_PASSWORD = "Admin@123"

    # Default fallback policy when no firewall rule matches ("DENY" or "ALLOW")
    DEFAULT_POLICY = "DENY"
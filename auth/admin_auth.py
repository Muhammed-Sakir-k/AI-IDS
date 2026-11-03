# ============================================================
# AI-IDS — Admin Authentication
# File: auth/admin_auth.py
# ============================================================

import hashlib
import json
import os

ADMIN_FILE = os.path.join(os.path.dirname(__file__), "admin_config.json")

# Default credentials — admin / admin123
# These get updated when admin changes password from the panel
DEFAULT_CONFIG = {
    "username": "admin",
    "password_hash": hashlib.sha256("admin123".encode()).hexdigest(),
    "created_at": "2026-01-01"
}


def _load_config():
    if not os.path.exists(ADMIN_FILE):
        _save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG
    with open(ADMIN_FILE, "r") as f:
        return json.load(f)


def _save_config(config):
    os.makedirs(os.path.dirname(ADMIN_FILE), exist_ok=True)
    with open(ADMIN_FILE, "w") as f:
        json.dump(config, f, indent=2)


def verify_login(username, password):
    config = _load_config()
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return (username == config["username"] and
            hashed   == config["password_hash"])


def change_password(old_password, new_password):
    config = _load_config()
    old_hash = hashlib.sha256(old_password.encode()).hexdigest()
    if old_hash != config["password_hash"]:
        return False, "Current password is incorrect"
    if len(new_password) < 6:
        return False, "New password must be at least 6 characters"
    config["password_hash"] = hashlib.sha256(new_password.encode()).hexdigest()
    _save_config(config)
    return True, "Password changed successfully"


def get_username():
    return _load_config()["username"]
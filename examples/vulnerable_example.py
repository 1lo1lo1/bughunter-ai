"""
BugHunter AI — Example Vulnerable Code
This file is intentionally vulnerable for testing purposes.
DO NOT use in production!
"""

# ── SQL Injection ──────────────────────────────────────────
import sqlite3

def get_user_insecure(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULN: SQL Injection via string concatenation
    cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")
    return cursor.fetchone()

def get_user_secure(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SAFE: Parameterized query
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()

# ── Command Injection ──────────────────────────────────────
import os
import subprocess

def ping_host_insecure(host):
    # VULN: OS Command Injection
    os.system("ping -c 1 " + host)

def ping_host_secure(host):
    # SAFE: List arguments, no shell
    subprocess.run(["ping", "-c", "1", host], capture_output=True)

# ── Hardcoded Secrets ──────────────────────────────────────
# VULN: Hardcoded credentials
DATABASE_PASSWORD = "super_secret_password_123"
SECRET_KEY = "my-very-secret-key-that-should-not-be-here"
API_KEY = "sk-1234567890abcdef1234567890abcdef"

# ── Unsafe Deserialization ─────────────────────────────────
import pickle
import yaml

def load_data_insecure(data):
    # VULN: Arbitrary code execution via pickle
    return pickle.loads(data)

def load_yaml_insecure(data):
    # VULN: yaml.load without SafeLoader
    return yaml.load(data)

def load_yaml_secure(data):
    # SAFE: SafeLoader
    return yaml.safe_load(data)

# ── Weak Cryptography ──────────────────────────────────────
import hashlib
import random

def hash_password_insecure(password):
    # VULN: MD5 is broken
    return hashlib.md5(password.encode()).hexdigest()

def generate_token_insecure():
    # VULN: Weak PRNG
    return str(random.randint(100000, 999999))

def generate_token_secure():
    import secrets
    # SAFE: Cryptographically secure
    return secrets.token_hex(32)

# ── Path Traversal ─────────────────────────────────────────
def read_file_insecure(filename):
    # VULN: Path traversal - attacker can read ../../etc/passwd
    with open(filename) as f:
        return f.read()

def read_file_secure(filename, base_dir="/var/www/files"):
    import os
    # SAFE: Validate path is within base_dir
    safe_path = os.path.abspath(os.path.join(base_dir, filename))
    if not safe_path.startswith(os.path.abspath(base_dir)):
        raise ValueError("Path traversal detected!")
    with open(safe_path) as f:
        return f.read()

# ── SSRF ───────────────────────────────────────────────────
import requests

def fetch_url_insecure(url):
    # VULN: SSRF — attacker can fetch internal resources
    return requests.get(url).text

# ── Debug Mode ─────────────────────────────────────────────
DEBUG = True  # VULN: Debug mode enabled

# ── Assert for Security ────────────────────────────────────
def admin_only_insecure(user):
    # VULN: Assert removed with -O flag!
    assert user.is_admin, "Not an admin"
    return "Admin data"

def admin_only_secure(user):
    # SAFE: Proper check
    if not user.is_admin:
        raise PermissionError("Not an admin")
    return "Admin data"

import os
import sqlite3
import hashlib
from typing import Optional
from datetime import datetime

BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, 'data')
UPLOAD_DIR = os.path.join(DATA_DIR, 'uploads')
DB_PATH = os.path.join(DATA_DIR, 'app.db')

os.makedirs(UPLOAD_DIR, exist_ok=True)


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _conn()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            totp TEXT,
            email TEXT,
            sso_provider TEXT,
            vault_salt TEXT,
            vault_verifier TEXT,
            created_at TEXT NOT NULL
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            orig_filename TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            container_sha256 TEXT NOT NULL,
            plaintext_sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username)
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            event_type TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def log_event(username: Optional[str], event_type: str, status: str, details: str = ''):
    conn = _conn()
    conn.execute(
        'INSERT INTO audit_log (username, event_type, status, details, created_at) VALUES (?, ?, ?, ?, ?)',
        (username, event_type, status, details, datetime.utcnow().isoformat(timespec='seconds')),
    )
    conn.commit()
    conn.close()


def get_audit_for_user(username: str, limit: int = 100):
    conn = _conn()
    rows = conn.execute(
        'SELECT id, username, event_type, status, details, created_at FROM audit_log WHERE username = ? OR username IS NULL ORDER BY id DESC LIMIT ?',
        (username, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_user(username: str) -> Optional[dict]:
    conn = _conn()
    row = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_email(email: str) -> Optional[dict]:
    conn = _conn()
    row = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_user_local(username: str, password_hash: str, totp_secret: str):
    conn = _conn()
    conn.execute(
        'INSERT INTO users (username, password, totp, email, sso_provider, vault_salt, vault_verifier, created_at) VALUES (?, ?, ?, NULL, NULL, NULL, NULL, ?)',
        (username, password_hash, totp_secret, datetime.utcnow().isoformat(timespec='seconds')),
    )
    conn.commit()
    conn.close()
    return get_user(username)


def create_or_update_user_sso(provider: str, email: str, username_hint: str):
    existing = get_user_by_email(email)
    if existing:
        conn = _conn()
        conn.execute('UPDATE users SET sso_provider = ? WHERE username = ?', (provider, existing['username']))
        conn.commit()
        conn.close()
        return get_user(existing['username'])

    username = username_hint or 'user'
    base = username
    i = 1
    while get_user(username):
        i += 1
        username = f'{base}{i}'

    conn = _conn()
    conn.execute(
        'INSERT INTO users (username, password, totp, email, sso_provider, vault_salt, vault_verifier, created_at) VALUES (?, NULL, NULL, ?, ?, NULL, NULL, ?)',
        (username, email, provider, datetime.utcnow().isoformat(timespec='seconds')),
    )
    conn.commit()
    conn.close()
    return get_user(username)


def set_user_vault(username: str, salt_b64: str, verifier_b64: str):
    conn = _conn()
    conn.execute('UPDATE users SET vault_salt = ?, vault_verifier = ? WHERE username = ?', (salt_b64, verifier_b64, username))
    conn.commit()
    conn.close()


def add_file_record(username: str, orig_filename: str, stored_name: str, container_sha256: str, plaintext_sha256: str, size_bytes: int):
    conn = _conn()
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO files (username, orig_filename, stored_name, container_sha256, plaintext_sha256, size_bytes, uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (username, orig_filename, stored_name, container_sha256, plaintext_sha256, size_bytes, datetime.utcnow().isoformat(timespec='seconds')),
    )
    conn.commit()
    file_id = cur.lastrowid
    conn.close()
    return get_file_record(file_id)


def list_files_for_user(username: str):
    conn = _conn()
    rows = conn.execute(
        'SELECT id, orig_filename, stored_name, container_sha256, plaintext_sha256, size_bytes, uploaded_at FROM files WHERE username = ? ORDER BY id DESC',
        (username,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_file_record(file_id: int):
    conn = _conn()
    row = conn.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def delete_file_record(file_id: int):
    row = get_file_record(file_id)
    if not row:
        return None
    path = os.path.join(UPLOAD_DIR, row['stored_name'])
    if os.path.exists(path):
        os.remove(path)
    conn = _conn()
    conn.execute('DELETE FROM files WHERE id = ?', (file_id,))
    conn.commit()
    conn.close()
    return row


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

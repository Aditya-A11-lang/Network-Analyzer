"""Local username/password accounts with role-based access control."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
from datetime import datetime, timezone

from . import database

ROLES = ("user", "admin")
PASSWORD_ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 12
_USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
_DUMMY_SALT = b"network-analyzer-login-check"
_DUMMY_HASH = hashlib.pbkdf2_hmac(
    "sha256", b"not-a-password", _DUMMY_SALT, PASSWORD_ITERATIONS
)


class IAMError(Exception):
    """Raised when an account operation is invalid or not authorized."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_username(username: str) -> str:
    normalized = username.strip().casefold()
    if not _USERNAME_PATTERN.fullmatch(normalized):
        raise ValueError("Username must be 3–32 characters: letters, numbers, dots, dashes, or underscores.")
    return normalized


def _hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > 1024:
        raise ValueError("Password must be no longer than 1024 characters.")
    password_salt = salt or secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        password_salt,
        PASSWORD_ITERATIONS,
    )
    return password_salt.hex(), password_hash.hex()


def _audit(conn, actor: str | None, target: str | None, action: str, details: str = "") -> None:
    conn.execute(
        """INSERT INTO iam_audit_log
           (timestamp, actor_subject, target_subject, action, details)
           VALUES (?, ?, ?, ?, ?)""",
        (_now(), actor, target, action, details),
    )


def has_accounts() -> bool:
    with database.get_connection() as conn:
        return conn.execute("SELECT 1 FROM local_accounts LIMIT 1").fetchone() is not None


def _account_row(conn, username: str):
    return conn.execute(
        """SELECT username AS subject, username, full_name, role, is_active,
                  created_at, last_login
           FROM local_accounts WHERE username = ?""",
        (username,),
    ).fetchone()


def get_user(username: str) -> dict | None:
    normalized = _normalize_username(username)
    with database.get_connection() as conn:
        row = _account_row(conn, normalized)
        return dict(row) if row is not None else None


def _insert_account(conn, username: str, password: str, full_name: str, role: str) -> None:
    normalized = _normalize_username(username)
    if role not in ROLES:
        raise ValueError("Choose either the user or admin role.")
    salt, password_hash = _hash_password(password)
    now = _now()
    try:
        conn.execute(
            """INSERT INTO local_accounts
               (username, password_hash, salt, full_name, role, is_active, created_at, last_login)
               VALUES (?, ?, ?, ?, ?, 1, ?, ?)""",
            (normalized, password_hash, salt, full_name.strip(), role, now, now),
        )
    except sqlite3.IntegrityError as exc:
        raise IAMError("That username is already in use.") from exc


def create_first_admin(username: str, password: str, full_name: str = "") -> dict:
    """Create the initial administrator exactly once, during first-run setup."""
    with database.get_connection() as conn:
        if conn.execute("SELECT 1 FROM local_accounts LIMIT 1").fetchone() is not None:
            raise IAMError("Initial setup is already complete. Sign in with an administrator account.")
        _insert_account(conn, username, password, full_name, "admin")
        normalized = _normalize_username(username)
        _audit(conn, normalized, normalized, "initial_admin_created")
        return dict(_account_row(conn, normalized))


def authenticate_user(username: str, password: str) -> dict | None:
    """Validate a local account and record a successful sign-in."""
    if len(password) > 1024:
        return None
    try:
        normalized = _normalize_username(username)
    except ValueError:
        normalized = ""

    with database.get_connection() as conn:
        row = conn.execute(
            """SELECT username, password_hash, salt, full_name, role, is_active,
                      created_at, last_login
               FROM local_accounts WHERE username = ?""",
            (normalized,),
        ).fetchone()
        if row is None:
            salt = _DUMMY_SALT
            expected_hash = _DUMMY_HASH
        else:
            salt = bytes.fromhex(row["salt"])
            expected_hash = bytes.fromhex(row["password_hash"])

        supplied_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PASSWORD_ITERATIONS,
        )
        if (
            row is None
            or not row["is_active"]
            or not hmac.compare_digest(supplied_hash, expected_hash)
        ):
            return None

        now = _now()
        conn.execute(
            "UPDATE local_accounts SET last_login = ? WHERE username = ?",
            (now, normalized),
        )
        _audit(conn, normalized, normalized, "sign_in")
        result = dict(_account_row(conn, normalized))
        return result


def _require_active_admin(conn, actor: str) -> None:
    row = conn.execute(
        "SELECT role, is_active FROM local_accounts WHERE username = ?",
        (_normalize_username(actor),),
    ).fetchone()
    if row is None or not row["is_active"] or row["role"] != "admin":
        raise IAMError("An active administrator account is required.")


def create_user(
    username: str,
    password: str,
    full_name: str,
    role: str,
    actor: str,
) -> None:
    with database.get_connection() as conn:
        _require_active_admin(conn, actor)
        _insert_account(conn, username, password, full_name, role)
        normalized = _normalize_username(username)
        _audit(conn, _normalize_username(actor), normalized, "account_created", f"role={role}")


def list_users() -> list[dict]:
    with database.get_connection() as conn:
        rows = conn.execute(
            """SELECT username AS subject, username, full_name, role, is_active,
                      created_at, last_login
               FROM local_accounts ORDER BY username COLLATE NOCASE"""
        ).fetchall()
        return [dict(row) for row in rows]


def list_audit_events(limit: int = 100) -> list[dict]:
    if not 1 <= limit <= 500:
        raise ValueError("Audit event limit must be between 1 and 500.")
    with database.get_connection() as conn:
        rows = conn.execute(
            """SELECT timestamp, actor_subject, target_subject, action, details
               FROM iam_audit_log ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def update_user_role(target: str, role: str, actor: str) -> None:
    if role not in ROLES:
        raise ValueError("Choose either the user or admin role.")
    target_name = _normalize_username(target)
    actor_name = _normalize_username(actor)
    with database.get_connection() as conn:
        _require_active_admin(conn, actor_name)
        account = conn.execute(
            "SELECT role, is_active FROM local_accounts WHERE username = ?",
            (target_name,),
        ).fetchone()
        if account is None:
            raise IAMError("The selected account no longer exists.")
        if account["role"] == "admin" and account["is_active"] and role != "admin":
            count = conn.execute(
                "SELECT COUNT(*) AS total FROM local_accounts WHERE role = 'admin' AND is_active = 1"
            ).fetchone()["total"]
            if count <= 1:
                raise IAMError("The last active administrator cannot be demoted.")
        conn.execute("UPDATE local_accounts SET role = ? WHERE username = ?", (role, target_name))
        _audit(conn, actor_name, target_name, "role_changed", f"role={role}")


def update_user_active_state(target: str, is_active: bool, actor: str) -> None:
    target_name = _normalize_username(target)
    actor_name = _normalize_username(actor)
    with database.get_connection() as conn:
        _require_active_admin(conn, actor_name)
        account = conn.execute(
            "SELECT role, is_active FROM local_accounts WHERE username = ?",
            (target_name,),
        ).fetchone()
        if account is None:
            raise IAMError("The selected account no longer exists.")
        if not is_active and account["role"] == "admin" and account["is_active"]:
            count = conn.execute(
                "SELECT COUNT(*) AS total FROM local_accounts WHERE role = 'admin' AND is_active = 1"
            ).fetchone()["total"]
            if count <= 1:
                raise IAMError("The last active administrator cannot be disabled.")
        conn.execute(
            "UPDATE local_accounts SET is_active = ? WHERE username = ?",
            (int(is_active), target_name),
        )
        _audit(
            conn,
            actor_name,
            target_name,
            "account_enabled" if is_active else "account_disabled",
        )


def reset_user_password(target: str, password: str, actor: str) -> None:
    target_name = _normalize_username(target)
    actor_name = _normalize_username(actor)
    salt, password_hash = _hash_password(password)
    with database.get_connection() as conn:
        _require_active_admin(conn, actor_name)
        cursor = conn.execute(
            "UPDATE local_accounts SET password_hash = ?, salt = ? WHERE username = ?",
            (password_hash, salt, target_name),
        )
        if cursor.rowcount == 0:
            raise IAMError("The selected account no longer exists.")
        _audit(conn, actor_name, target_name, "password_reset")

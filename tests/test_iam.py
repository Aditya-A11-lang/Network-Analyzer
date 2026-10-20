import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest

from src import database, iam


@pytest.fixture
def isolated_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "iam-test.db"))
    database.init_db()


def test_first_run_creates_admin_and_password_is_hashed(isolated_database):
    admin = iam.create_first_admin("NetworkAdmin", "a long secure passphrase", "Network Admin")

    assert admin["username"] == "networkadmin"
    assert admin["role"] == "admin"
    assert iam.has_accounts()
    with database.get_connection() as conn:
        row = conn.execute(
            "SELECT password_hash, salt FROM local_accounts WHERE username = ?",
            ("networkadmin",),
        ).fetchone()
    assert row["password_hash"] != "a long secure passphrase"
    assert len(row["salt"]) == 32


def test_first_admin_setup_only_runs_once(isolated_database):
    iam.create_first_admin("networkadmin", "a long secure passphrase")

    with pytest.raises(iam.IAMError, match="already complete"):
        iam.create_first_admin("anotheradmin", "another secure passphrase")


def test_local_authentication_and_admin_managed_user(isolated_database):
    admin = iam.create_first_admin("networkadmin", "a long secure passphrase")

    assert iam.authenticate_user("NETWORKADMIN", "a long secure passphrase")["role"] == "admin"
    assert iam.authenticate_user("networkadmin", "incorrect password") is None

    iam.create_user(
        "analyst_user",
        "another secure passphrase",
        "Traffic Analyst",
        "user",
        admin["username"],
    )
    user = iam.authenticate_user("analyst_user", "another secure passphrase")
    assert user["role"] == "user"
    assert user["full_name"] == "Traffic Analyst"
    assert iam.authenticate_user("analyst_user", "another secure passphrase")["username"] == "analyst_user"

    with pytest.raises(iam.IAMError, match="administrator"):
        iam.create_user("blocked_user", "some secure password", "", "user", "analyst_user")


def test_admin_can_reset_password_and_change_roles(isolated_database):
    admin = iam.create_first_admin("networkadmin", "a long secure passphrase")
    iam.create_user("analyst_user", "another secure passphrase", "", "user", admin["username"])

    iam.reset_user_password("analyst_user", "replacement secure passphrase", admin["username"])
    iam.update_user_role("analyst_user", "admin", admin["username"])

    assert iam.authenticate_user("analyst_user", "another secure passphrase") is None
    assert iam.authenticate_user("analyst_user", "replacement secure passphrase")["role"] == "admin"
    assert any(event["action"] == "password_reset" for event in iam.list_audit_events())
    assert any(event["action"] == "role_changed" for event in iam.list_audit_events())


def test_last_active_admin_cannot_be_demoted_or_disabled(isolated_database):
    admin = iam.create_first_admin("networkadmin", "a long secure passphrase")

    with pytest.raises(iam.IAMError, match="last active administrator"):
        iam.update_user_role(admin["username"], "user", admin["username"])
    with pytest.raises(iam.IAMError, match="last active administrator"):
        iam.update_user_active_state(admin["username"], False, admin["username"])


def test_password_and_username_require_valid_values(isolated_database):
    with pytest.raises(ValueError, match="at least"):
        iam.create_first_admin("networkadmin", "short")
    with pytest.raises(ValueError, match="Username"):
        iam.create_first_admin("x", "a long secure passphrase")


def test_local_theme_preference_is_persisted_per_account(isolated_database):
    admin = iam.create_first_admin("networkadmin", "a long secure passphrase")

    assert database.get_user_theme(admin["username"]) == "Dark"
    database.set_user_theme(admin["username"], "Dark")
    assert database.get_user_theme("NETWORKADMIN") == "Dark"

    with pytest.raises(ValueError, match="Theme"):
        database.set_user_theme(admin["username"], "Neon")

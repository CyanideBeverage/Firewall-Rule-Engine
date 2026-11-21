"""
Authentication and access control module.
Implements secure password verification, input validation, and session guards.
"""

from functools import wraps
from flask import session, redirect, url_for, flash
from werkzeug.security import check_password_hash
from database import get_user_by_username


def authenticate_user(username: str, password: str, db_path: str = None):
    """
    Authenticates an administrator safely.
    - Rejects empty inputs or excessively long values.
    - Fetches user via parameterized SQL query (immune to SQL injection).
    - Verifies password using constant-time cryptographic hash comparison.

    Returns:
        tuple: (success: bool, user_dict_or_none: dict | None, message: str)
    """
    if not username or not password:
        return False, None, "Username and password are required."

    cleaned_username = username.strip()
    if len(cleaned_username) > 64 or len(password) > 128:
        return False, None, "Invalid credentials length."

    # Parameterized lookup ensures SQL payloads like "' OR '1'='1' --"
    # are treated strictly as literal username text, never executable SQL.
    user = get_user_by_username(cleaned_username, db_path=db_path)
    if user is None:
        return False, None, "Invalid username or password."

    if not check_password_hash(user["password_hash"], password):
        return False, None, "Invalid username or password."

    return True, user, "Login successful."


def login_required(view_func):
    """Decorator restricting route access to authenticated administrators."""
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access the Firewall Management Console.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped_view
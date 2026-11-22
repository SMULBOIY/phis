"""Authentication business logic (Stage 8).

Blueprints stay thin: ``routes/auth.py`` parses input and delegates here. This
module owns validation, password policy, hashing, lookup and session bookkeeping.

Security properties
-------------------
* ``werkzeug.security.generate_password_hash(..., method="scrypt")`` produces a
  salted, computationally expensive hash. Plaintext never reaches the database,
  a log line, a response or an exception message.
* Registration uses ``email-validator`` (already pinned in requirements.txt).
* Uniqueness is checked case-insensitively and the database UNIQUE constraints
  are the final authority; ``IntegrityError`` is translated into one generic
  message so the response cannot be used for fine-grained account enumeration.
* A missing account still performs one scrypt verification against a dummy hash,
  so "unknown user" and "wrong password" take comparable time.
* Self-registration ALWAYS creates ``role='user'``. The ``role`` argument of
  ``create_user`` exists only for ``scripts/create_admin.py`` and is never read
  from request data by any route.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from email_validator import EmailNotValidError, validate_email
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db
from models.database_models import ROLES, User, utcnow

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

# Deliberately short: these are classic weak choices, not a password dictionary.
COMMON_PASSWORDS = frozenset({
    "password", "password1", "password123", "password123!", "password1!",
    "12345678", "123456789", "1234567890", "qwerty123", "qwertyuiop",
    "letmein", "admin123", "admin1234", "welcome1", "welcome123",
    "iloveyou", "phishing", "changeme", "abc12345",
})


class RegistrationError(ValueError):
    """A safe, displayable validation failure. Never contains a password."""


def normalize_username(value: Any) -> str:
    """Trim surrounding whitespace; keep the original case for display."""
    return value.strip() if isinstance(value, str) else ""


def normalize_email(value: Any) -> str:
    """Lower-case and trim an email address; never echo it into an error."""
    return value.strip().lower() if isinstance(value, str) else ""


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    """One scrypt hash used to equalise timing for unknown accounts."""
    return generate_password_hash(
        "timing-equalisation-value-not-a-real-account", method="scrypt"
    )


def validate_password(
    password: Any, *, username: str = "", email: str = ""
) -> list[str]:
    """Return a list of safe, displayable policy violations (empty = valid)."""
    problems: list[str] = []
    if not isinstance(password, str) or not password:
        return ["A password is required."]
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"Use at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > MAX_PASSWORD_LENGTH:
        problems.append(f"Use at most {MAX_PASSWORD_LENGTH} characters.")
    if not any(char.isupper() for char in password):
        problems.append("Include an uppercase letter.")
    if not any(char.islower() for char in password):
        problems.append("Include a lowercase letter.")
    if not any(char.isdigit() for char in password):
        problems.append("Include a digit.")
    if not any(not char.isalnum() for char in password):
        problems.append("Include a symbol.")
    if "\x00" in password or "\n" in password or "\r" in password:
        problems.append("Control characters are not allowed.")
    if password.strip().lower() in COMMON_PASSWORDS:
        problems.append("That password is too common.")
    if username and password.strip().lower() == username.strip().lower():
        problems.append("Do not use your username as the password.")
    if email and password.strip().lower() == email.strip().lower():
        problems.append("Do not use your email address as the password.")
    return problems


def validate_registration(
    username: Any, email: Any, password: Any, confirm_password: Any = None
) -> tuple[str, str, list[str]]:
    """Validate inputs and return ``(username, email, problems)``.

    Problem strings are safe to show to the user: none contains the submitted
    password, and the email error is generic rather than the raw library text.
    """
    clean_username = normalize_username(username)
    clean_email = normalize_email(email)
    problems: list[str] = []

    if not USERNAME_PATTERN.fullmatch(clean_username):
        problems.append(
            "Username must be 3-32 characters: letters, digits, dot, dash or underscore."
        )
    if len(clean_email) > 254:
        problems.append("Email address is too long.")
    elif clean_email:
        try:
            validated = validate_email(clean_email, check_deliverability=False)
            clean_email = validated.normalized.lower()
        except EmailNotValidError:
            problems.append("Enter a valid email address.")
    else:
        problems.append("An email address is required.")

    problems.extend(validate_password(
        password, username=clean_username, email=clean_email
    ))
    if confirm_password is not None and confirm_password != password:
        problems.append("The two passwords do not match.")

    return clean_username, clean_email, problems


def create_user(
    username: Any,
    email: Any,
    password: Any,
    *,
    role: str = "user",
) -> User:
    """Validate, hash and persist a new account. Returns the ORM object.

    Raises ``RegistrationError`` with a displayable message on any validation
    or uniqueness failure. ``role`` is an internal parameter used only by the
    admin bootstrap script; routes never pass user-controlled values here.
    """
    if role not in ROLES:
        raise ValueError(f"Unsupported role: {role!r}")
    clean_username, clean_email, problems = validate_registration(
        username, email, password
    )
    if problems:
        raise RegistrationError(" ".join(problems))

    existing = db.session.query(User).filter(
        or_(
            func.lower(User.username) == clean_username.lower(),
            func.lower(User.email) == clean_email.lower(),
        )
    ).first()
    if existing is not None:
        raise RegistrationError("That username or email is already registered.")

    user = User(
        username=clean_username,
        email=clean_email,
        role=role,
        active=True,
        created_at=utcnow(),
    )
    user.set_password(password)
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise RegistrationError("That username or email is already registered.") from exc
    return user


def authenticate(identifier: Any, password: Any) -> User | None:
    """Return the active user for valid credentials, else ``None``.

    The same generic outcome is produced for an unknown account, a wrong
    password and a disabled account, so callers cannot enumerate users.
    """
    if not isinstance(identifier, str) or not isinstance(password, str):
        return None
    clean = identifier.strip()
    if not clean or not password:
        return None

    try:
        user = db.session.query(User).filter(
            or_(
                func.lower(User.username) == clean.lower(),
                func.lower(User.email) == clean.lower(),
            )
        ).first()
    except SQLAlchemyError:
        db.session.rollback()
        return None

    if user is None:
        check_password_hash(_dummy_hash(), password)
        return None
    if not user.check_password(password) or not user.is_active:
        return None
    return user


def record_login(user: User) -> None:
    """Store the last successful sign-in time in UTC."""
    user.last_login_at = utcnow()
    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()


def get_user_by_id(user_id: Any) -> User | None:
    """Flask-Login ``user_loader`` callback. Fails closed on any problem."""
    try:
        numeric = int(user_id)
    except (TypeError, ValueError):
        return None
    if numeric <= 0:
        return None
    try:
        user = db.session.get(User, numeric)
    except SQLAlchemyError:
        db.session.rollback()
        return None
    return user if user is not None and user.is_active else None


__all__ = [
    "RegistrationError", "MIN_PASSWORD_LENGTH", "MAX_PASSWORD_LENGTH",
    "USERNAME_PATTERN", "normalize_username", "normalize_email",
    "validate_password", "validate_registration", "create_user",
    "authenticate", "record_login", "get_user_by_id",
]

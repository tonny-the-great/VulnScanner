"""
Password policy shared by registration, password changes and the bootstrap superuser.

Length is the main requirement (NIST SP 800-63B style): no composition rules,
but obviously guessable choices are rejected.
"""

from __future__ import annotations

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 256

# Common passwords that satisfy the length requirement. Compared case-insensitively
# and as a whole, so longer passphrases that merely contain these still pass.
COMMON_PASSWORDS: frozenset[str] = frozenset({
    "password1234",
    "password12345",
    "password123!",
    "passwordpassword",
    "p@ssw0rd1234",
    "passw0rd1234",
    "123456789012",
    "1234567890123",
    "qwertyuiop12",
    "qwertyuiop123",
    "qwerty123456",
    "1q2w3e4r5t6y",
    "1qaz2wsx3edc",
    "zaq12wsxcde3",
    "abcdefghijkl",
    "administrator",
    "adminadmin12",
    "letmein12345",
    "welcome12345",
    "changeme1234",
    "iloveyou1234",
})


def password_policy_problems(password: str, email: str | None = None) -> list[str]:
    """Return user-facing reasons the password is unacceptable (empty when it is fine)."""
    problems: list[str] = []
    if len(password) < PASSWORD_MIN_LENGTH:
        problems.append(f"Password must be at least {PASSWORD_MIN_LENGTH} characters long")
    if len(password) > PASSWORD_MAX_LENGTH:
        problems.append(f"Password must be at most {PASSWORD_MAX_LENGTH} characters long")
    if password and len(set(password)) == 1:
        problems.append("Password must not be a single repeated character")
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        problems.append("Password is too common; choose a less predictable one")
    if email:
        local_part = email.split("@", 1)[0].strip().lower()
        if len(local_part) >= 4 and local_part in lowered:
            problems.append("Password must not contain the name part of your email address")
    return problems


def validate_password_policy(password: str, email: str | None = None) -> None:
    """Raise ValueError listing every policy problem with the password."""
    problems = password_policy_problems(password, email)
    if problems:
        raise ValueError("; ".join(problems))

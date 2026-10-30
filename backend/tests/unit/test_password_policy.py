"""Password policy: length first, plus rejection of obviously guessable choices."""

import pytest

from app.core.password_policy import (
    COMMON_PASSWORDS,
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    password_policy_problems,
    validate_password_policy,
)


@pytest.mark.parametrize("password", [
    "WorkflowPassword123!",
    "correct horse battery staple",
    "Platform-Bootstrap-Secret-2026!",
    "x" * 11 + "y",
])
def test_reasonable_passwords_pass(password):
    assert password_policy_problems(password) == []
    validate_password_policy(password, "someone@example.com")


def test_length_bounds():
    assert PASSWORD_MIN_LENGTH == 12
    short = password_policy_problems("Sh0rt!pass")
    assert len(short) == 1 and "at least 12" in short[0]
    assert password_policy_problems("a" * 11 + "b") == []
    long = password_policy_problems("ab" * (PASSWORD_MAX_LENGTH // 2) + "c")
    assert any("at most" in problem for problem in long)
    assert password_policy_problems("ab" * (PASSWORD_MAX_LENGTH // 2)) == []


def test_single_repeated_character_is_rejected():
    problems = password_policy_problems("a" * 20)
    assert any("repeated" in problem for problem in problems)


def test_common_passwords_are_rejected_case_insensitively():
    assert len(COMMON_PASSWORDS) >= 15
    assert all(len(p) >= PASSWORD_MIN_LENGTH and p == p.lower() for p in COMMON_PASSWORDS)
    assert any("common" in p for p in password_policy_problems("Password1234"))
    assert any("common" in p for p in password_policy_problems("QWERTY123456"))
    # Exact matches only: a longer passphrase containing a common one is fine.
    assert password_policy_problems("password1234 is not my password") == []


def test_email_name_must_not_appear_in_password():
    problems = password_policy_problems("Analyst-Jordan-2026!", "jordan@example.com")
    assert any("email" in problem for problem in problems)
    # Short local parts are too likely to collide with ordinary words.
    assert password_policy_problems("Bob-is-a-builder-2026", "bob@example.com") == []
    assert password_policy_problems("Analyst-Jordan-2026!", None) == []


def test_validate_reports_every_problem():
    with pytest.raises(ValueError) as excinfo:
        validate_password_policy("admin", "admin@example.com")
    message = str(excinfo.value)
    assert "at least 12" in message and "email" in message and "; " in message

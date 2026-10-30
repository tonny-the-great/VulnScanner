"""Password-bound session tokens, single-use token consumption and bounded hashing."""

import threading
import time
import uuid

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.config import get_settings
from app.core import security
from app.core.security import (
    SESSION_INVALID_DETAIL,
    consume_token_once,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    is_token_revoked,
    password_version,
    revoke_token,
)
from app.main import app
from app.models.user import User

PASSWORD = "SessionTokenPassword-2026!"


def claims(token: str) -> dict:
    return jwt.decode(token, get_settings().SESSION_SECRET, algorithms=["HS256"])


@pytest.fixture
def no_redis(monkeypatch):
    monkeypatch.setattr(security, "get_redis_safe", lambda: None)


@pytest.fixture
def db_user(db):
    user = User(
        email=f"tokens-{uuid.uuid4().hex}@example.com",
        display_name="Token Tester",
        password_hash=hash_password(PASSWORD),
    )
    db.add(user)
    db.commit()
    return user


# ── Password version claim ────────────────────────────────────────────────────

def test_tokens_carry_the_password_version():
    user_id = uuid.uuid4()
    access = claims(create_access_token(user_id, "$argon2id$example-hash"))
    refresh = claims(create_refresh_token(user_id, "$argon2id$example-hash"))
    assert access["pwv"] == refresh["pwv"] == password_version("$argon2id$example-hash")
    assert access["type"] == "access" and refresh["type"] == "refresh"
    assert access["jti"] != refresh["jti"]
    assert "pwv" not in claims(create_access_token(user_id))


def test_password_version_is_short_keyed_and_hash_specific():
    first = password_version("$argon2id$hash-one")
    assert len(first) == 16 and int(first, 16) >= 0
    assert first == password_version("$argon2id$hash-one")
    assert first != password_version("$argon2id$hash-two")


def test_token_without_password_version_is_rejected(db_user):
    client = TestClient(app)
    legacy = create_access_token(db_user.id)  # issued before sessions were password-bound
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {legacy}"})
    assert response.status_code == 401
    assert response.json()["detail"] == SESSION_INVALID_DETAIL

    stale = create_access_token(db_user.id, hash_password("Some-Other-Password-2026!"))
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {stale}"})
    assert response.status_code == 401

    current = create_access_token(db_user.id, db_user.password_hash)
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {current}"})
    assert response.status_code == 200
    assert response.json()["email"] == db_user.email


def test_refresh_token_without_password_version_is_rejected(db_user):
    client = TestClient(app)
    legacy = create_refresh_token(db_user.id)
    response = client.post("/api/v1/auth/refresh", headers={"Cookie": f"refresh_token={legacy}"})
    assert response.status_code == 401
    assert response.json()["detail"] == SESSION_INVALID_DETAIL


# ── Single-use consumption ────────────────────────────────────────────────────

def test_consume_token_once_fallback_is_single_use(no_redis):
    jti = uuid.uuid4().hex
    assert consume_token_once(jti, 60) is True
    assert consume_token_once(jti, 60) is False
    # A consumed token also counts as revoked.
    assert is_token_revoked(jti)


def test_consume_token_once_fallback_allows_reuse_after_expiry(no_redis):
    jti = uuid.uuid4().hex
    assert consume_token_once(jti, 60) is True
    with security._revocation_lock:
        security._REVOKED_TOKENS_FALLBACK[jti] = time.time() - 1
    assert not is_token_revoked(jti)
    assert consume_token_once(jti, 60) is True


def test_revoked_token_cannot_be_consumed(no_redis):
    token = create_refresh_token(uuid.uuid4(), "$argon2id$hash")
    jti = claims(token)["jti"]
    revoke_token(token)
    assert consume_token_once(jti, 60) is False


def test_consume_token_once_has_exactly_one_winner_across_threads(no_redis):
    jti = uuid.uuid4().hex
    results: list[bool] = []
    barrier = threading.Barrier(16)

    def worker() -> None:
        barrier.wait()
        results.append(consume_token_once(jti, 60))

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 1 and results.count(False) == 15


class FakeRedis:
    def __init__(self, fail: bool = False):
        self.fail = fail
        self.calls: list[tuple] = []
        self.store: dict[str, str] = {}

    def set(self, key, value, nx=False, ex=None):
        self.calls.append((key, value, nx, ex))
        if self.fail:
            raise ConnectionError("redis down")
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    def exists(self, key):
        if self.fail:
            raise ConnectionError("redis down")
        return int(key in self.store)


def test_consume_token_once_uses_redis_set_nx(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(security, "get_redis_safe", lambda: fake)
    jti = uuid.uuid4().hex
    assert consume_token_once(jti, 120) is True
    assert consume_token_once(jti, 120) is False
    assert fake.calls[0] == (f"revoked_token:{jti}", "1", True, 120)
    assert is_token_revoked(jti)
    # An already-expired TTL still records the id for at least a second.
    assert consume_token_once(uuid.uuid4().hex, 0) is True
    assert fake.calls[-1][3] == 1


def test_consume_token_once_falls_back_when_redis_fails(monkeypatch):
    fake = FakeRedis(fail=True)
    failures: list[bool] = []
    monkeypatch.setattr(security, "get_redis_safe", lambda: fake)
    monkeypatch.setattr(security, "mark_redis_failed", lambda: failures.append(True))
    jti = uuid.uuid4().hex
    assert consume_token_once(jti, 60) is True
    assert failures
    # The in-process record keeps the id used even once Redis answers again.
    monkeypatch.setattr(security, "get_redis_safe", lambda: FakeRedis())
    assert consume_token_once(jti, 60) is False


def test_decode_token_can_skip_the_revocation_check(no_redis):
    token = create_refresh_token(uuid.uuid4(), "$argon2id$hash")
    revoke_token(token)
    with pytest.raises(HTTPException) as excinfo:
        decode_token(token, expected_type="refresh")
    assert excinfo.value.status_code == 401
    assert decode_token(token, expected_type="refresh", check_revoked=False)["type"] == "refresh"
    with pytest.raises(HTTPException):
        decode_token(token, expected_type="access", check_revoked=False)


# ── Bounded hashing ───────────────────────────────────────────────────────────

def test_password_hashing_concurrency_is_bounded(monkeypatch):
    active = 0
    peak = 0
    lock = threading.Lock()

    class SlowHasher:
        def _work(self) -> None:
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.05)
            with lock:
                active -= 1

        def hash(self, plain):
            self._work()
            return "hashed"

        def verify(self, stored_hash, plain):
            self._work()
            return True

    monkeypatch.setattr(security, "_ph", SlowHasher())
    monkeypatch.setattr(security, "_hash_slots", threading.BoundedSemaphore(2))

    def run(index: int) -> None:
        if index % 2:
            assert hash_password("p") == "hashed"
        else:
            assert security.verify_password("h", "p") is True

    threads = [threading.Thread(target=run, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert 1 <= peak <= 2


def test_verify_password_never_raises():
    assert security.verify_password("not-an-argon2-hash", "whatever") is False
    assert security.needs_rehash("not-an-argon2-hash") is False


def test_hashing_refuses_instead_of_waiting_forever(monkeypatch):
    from app.core.exceptions import RateLimitExceededError

    busy = threading.BoundedSemaphore(1)
    busy.acquire()
    monkeypatch.setattr(security, "_hash_slots", busy)
    monkeypatch.setattr(security, "_HASH_SLOT_WAIT_SECONDS", 0.05)
    # An overloaded server is not a wrong password: it raises rather than returning False.
    with pytest.raises(RateLimitExceededError):
        security.verify_password("h", "p")
    with pytest.raises(RateLimitExceededError):
        hash_password("p")
    busy.release()
    # The slot is returned after use, including when verification fails.
    assert security.verify_password("not-an-argon2-hash", "p") is False
    assert busy.acquire(timeout=0)

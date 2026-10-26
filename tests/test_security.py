from app.security import LoginThrottle, hash_password, verify_password


def test_password_hashing_round_trip():
    h = hash_password("correct horse battery staple")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "correct horse battery staple")
    assert not verify_password(h, "wrong")
    assert not verify_password("not-a-hash", "anything")


def test_throttle_locks_and_expires():
    now = [0.0]
    t = LoginThrottle(max_failures=3, window_seconds=60, clock=lambda: now[0])
    for _ in range(3):
        t.record_failure("a@x")
    assert t.is_locked("a@x")
    assert not t.is_locked("b@x")
    now[0] = 61
    assert not t.is_locked("a@x")


def test_throttle_reset():
    t = LoginThrottle(2, 60)
    t.record_failure("a@x")
    t.record_failure("a@x")
    t.reset("a@x")
    assert not t.is_locked("a@x")

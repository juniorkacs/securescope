import datetime as dt
import re

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

TODAY = dt.date(2026, 10, 26)


def make_settings(**kw):
    base = dict(
        database_url="sqlite:///:memory:",
        secret_key="test-secret-key-0123456789",
        demo_password="demo-pass-123",
    )
    base.update(kw)
    return Settings(**base)


@pytest.fixture
def app():
    return create_app(make_settings(), today=lambda: TODAY)


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


def csrf_of(client: TestClient, path: str = "/login") -> str:
    html = client.get(path).text
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    assert m, "no CSRF token on page"
    return m.group(1)


def sign_in(client: TestClient, role: str) -> str:
    token = csrf_of(client)
    r = client.post("/demo-login", data={"role": role, "csrf": token}, follow_redirects=False)
    assert r.status_code == 303
    return csrf_of(client, "/")


@pytest.fixture
def viewer(client):
    return client, sign_in(client, "viewer")


@pytest.fixture
def analyst(client):
    return client, sign_in(client, "analyst")


@pytest.fixture
def admin(client):
    return client, sign_in(client, "admin")

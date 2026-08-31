"""SM IAM 领域测试：用户、角色、登录、会话校验、MFA。"""

import pytest
from fastapi.testclient import TestClient

from app import base
from app.main import VERSION, app


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(base, "internal_api_key", lambda: "TEST")
    base.reset_state()
    from app.main import _init as init_db
    init_db()
    with TestClient(app) as c:
        c.headers["X-Internal-Token"] = "TEST"
        yield c


def test_health_and_version(client):
    r = client.get("/health", headers={"X-Request-Id": "suite-test"})
    assert r.status_code == 200
    assert r.json()["version"] == VERSION


def test_user_and_role_crud(client):
    assert client.post("/api/iam/roles", json={"name": "finance", "permissions": ["report.read"]}).status_code == 201
    assert client.post("/api/iam/users", json={"username": "alice", "email": "alice@corp.cn", "password": "Passw0rd!", "roles": ["finance"]}).status_code == 201
    assert client.post("/api/iam/users", json={"username": "alice", "email": "a2@corp.cn", "password": "Passw0rd!"}).status_code == 409
    assert client.get("/api/iam/users").json()["total"] == 1
    assert client.get("/api/iam/roles").json()["total"] == 1


def test_user_missing_role(client):
    assert client.post("/api/iam/users", json={"username": "bob", "email": "b@corp.cn", "password": "Passw0rd!", "roles": ["ghost"]}).status_code == 404


def test_login_verify_logout(client):
    client.post("/api/iam/users", json={"username": "alice", "email": "a@corp.cn", "password": "Passw0rd!"})
    assert client.post("/api/iam/auth/login", json={"username": "alice", "password": "wrong"}).status_code == 401
    login = client.post("/api/iam/auth/login", json={"username": "alice", "password": "Passw0rd!"}).json()
    token = login["token"]
    assert token.startswith("smt_")
    assert client.post("/api/iam/auth/verify", json={"token": token}).json()["valid"] is True
    assert client.post("/api/iam/auth/verify", json={"token": "invalid-token-value"}).status_code == 401
    assert client.post("/api/iam/auth/logout", json={"token": token}).json()["revoked"] is True
    assert client.post("/api/iam/auth/verify", json={"token": token}).status_code == 401


def test_user_status(client):
    uid = client.post("/api/iam/users", json={"username": "carol", "email": "c@corp.cn", "password": "Passw0rd!"}).json()["id"]
    assert client.post(f"/api/iam/users/{uid}/status", json={"status": "disabled"}).json()["status"] == "disabled"
    assert client.post("/api/iam/auth/login", json={"username": "carol", "password": "Passw0rd!"}).status_code == 403


def test_mfa(client):
    uid = client.post("/api/iam/users", json={"username": "dave", "email": "d@corp.cn", "password": "Passw0rd!"}).json()["id"]
    mfa = client.post(f"/api/iam/users/{uid}/mfa").json()
    assert mfa["mfa_enabled"] is True
    assert len(mfa["otpauth_secret"]) == 32


def test_stats(client):
    client.post("/api/iam/users", json={"username": "eve", "email": "e@corp.cn", "password": "Passw0rd!"})
    stats = client.get("/api/iam/stats").json()
    assert stats["users"] == 1
    assert stats["active_users"] == 1


def test_manifest_and_crypto(client):
    assert client.get("/api/integration/manifest").json()["version"] == VERSION
    enc = client.post("/api/crypto/encrypt", json={"value": "x"}).json()["ciphertext"]
    assert client.post("/api/crypto/decrypt", json={"value": enc}).json()["plaintext"] == "x"


def test_write_requires_auth(client):
    del client.headers["X-Internal-Token"]
    assert client.post("/api/iam/users", json={"username": "f", "email": "f@corp.cn", "password": "Passw0rd!"}).status_code == 401

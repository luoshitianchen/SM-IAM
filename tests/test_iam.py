"""IAM 业务深化测试：用户/角色/权限/客户端全生命周期。"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app

INTERNAL_TOKEN = "test-internal-key-12345"
AUTH_HEADERS = {"X-Internal-Token": INTERNAL_TOKEN}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# ═══════════════════════════════════════════════════════════
# 用户管理
# ═══════════════════════════════════════════════════════════

class TestUserManagement:
    def test_create_user_success(self, client):
        resp = client.post("/api/iam/users", json={
            "username": "testuser01", "password": "TestPass123",
            "display_name": "测试用户", "roles": ["viewer"],
        }, headers=AUTH_HEADERS)
        assert resp.status_code == 201
        data = resp.json()
        assert data["username"] == "testuser01"
        assert data["display_name"] == "测试用户"
        assert data["status"] == "active"
        assert "id" in data

    def test_create_user_requires_internal_token(self, client):
        resp = client.post("/api/iam/users", json={
            "username": "nouser", "password": "TestPass123",
        })
        assert resp.status_code in (401, 403)

    def test_create_user_duplicate_username(self, client):
        resp = client.post("/api/iam/users", json={
            "username": "testuser01", "password": "TestPass123",
        }, headers=AUTH_HEADERS)
        assert resp.status_code == 409

    def test_create_user_weak_password_rejected(self, client):
        resp = client.post("/api/iam/users", json={
            "username": "weakuser", "password": "alllowercase",
        }, headers=AUTH_HEADERS)
        assert resp.status_code == 400

    def test_list_users(self, client):
        resp = client.get("/api/iam/users", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert len(data["items"]) >= 1

    def test_get_user_by_id(self, client):
        list_resp = client.get("/api/iam/users", headers=AUTH_HEADERS)
        user_id = list_resp.json()["items"][0]["id"]
        resp = client.get(f"/api/iam/users/{user_id}", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["id"] == user_id

    def test_get_user_not_found(self, client):
        resp = client.get("/api/iam/users/nonexistent-id", headers=AUTH_HEADERS)
        assert resp.status_code == 404

    def test_update_user(self, client):
        list_resp = client.get("/api/iam/users?username=testuser01", headers=AUTH_HEADERS)
        items = list_resp.json()["items"]
        user = next((u for u in items if u["username"] == "testuser01"), None)
        assert user is not None
        resp = client.patch(f"/api/iam/users/{user['id']}", json={
            "display_name": "更新后的名称", "roles": ["admin", "viewer"],
        }, headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["display_name"] == "更新后的名称"
        assert "admin" in resp.json()["roles"]

    def test_update_user_status_disable(self, client):
        list_resp = client.get("/api/iam/users", headers=AUTH_HEADERS)
        user = next((u for u in list_resp.json()["items"] if u["username"] == "testuser01"), None)
        resp = client.patch(f"/api/iam/users/{user['id']}/status", json={
            "status": "disabled",
        }, headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["status"] == "disabled"

    def test_change_password(self, client):
        list_resp = client.get("/api/iam/users", headers=AUTH_HEADERS)
        user = next((u for u in list_resp.json()["items"] if u["username"] == "testuser01"), None)
        resp = client.post(f"/api/iam/users/{user['id']}/password", json={
            "old_password": "TestPass123", "new_password": "NewPass456",
        }, headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["password_changed"] is True

    def test_change_password_wrong_old(self, client):
        list_resp = client.get("/api/iam/users", headers=AUTH_HEADERS)
        user = next((u for u in list_resp.json()["items"] if u["username"] == "testuser01"), None)
        resp = client.post(f"/api/iam/users/{user['id']}/password", json={
            "old_password": "WrongPass", "new_password": "NewPass789",
        }, headers=AUTH_HEADERS)
        assert resp.status_code == 400


# ═══════════════════════════════════════════════════════════
# 角色管理
# ═══════════════════════════════════════════════════════════

class TestRoleManagement:
    def test_create_role_success(self, client):
        resp = client.post("/api/iam/roles", json={
            "name": "test-role-01", "description": "测试角色",
            "permissions": ["user:read", "user:write"],
        }, headers=AUTH_HEADERS)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "test-role-01"
        assert data["is_system"] is False
        assert "user:read" in data["permissions"]

    def test_create_role_duplicate_name(self, client):
        resp = client.post("/api/iam/roles", json={
            "name": "test-role-01", "description": "重复",
        }, headers=AUTH_HEADERS)
        assert resp.status_code == 409

    def test_list_roles(self, client):
        resp = client.get("/api/iam/roles", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

    def test_update_role(self, client):
        list_resp = client.get("/api/iam/roles", headers=AUTH_HEADERS)
        role = next((r for r in list_resp.json()["items"] if r["name"] == "test-role-01"), None)
        resp = client.patch(f"/api/iam/roles/{role['id']}", json={
            "description": "更新后的角色描述", "permissions": ["user:read"],
        }, headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["description"] == "更新后的角色描述"

    def test_delete_role(self, client):
        list_resp = client.get("/api/iam/roles", headers=AUTH_HEADERS)
        role = next((r for r in list_resp.json()["items"] if r["name"] == "test-role-01"), None)
        resp = client.delete(f"/api/iam/roles/{role['id']}", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True


# ═══════════════════════════════════════════════════════════
# 权限管理
# ═══════════════════════════════════════════════════════════

class TestPermissionManagement:
    def test_list_permissions(self, client):
        resp = client.get("/api/iam/permissions", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert "items" in resp.json()


# ═══════════════════════════════════════════════════════════
# 客户端管理
# ═══════════════════════════════════════════════════════════

class TestClientManagement:
    def test_create_client_success(self, client):
        resp = client.post("/api/iam/clients", json={
            "client_id": "test-client-01", "name": "测试客户端",
            "scopes": ["openid", "profile"],
        }, headers=AUTH_HEADERS)
        assert resp.status_code == 201
        data = resp.json()
        assert data["client_id"] == "test-client-01"
        assert "client_secret" in data
        assert len(data["client_secret"]) > 0

    def test_create_client_duplicate_id(self, client):
        resp = client.post("/api/iam/clients", json={
            "client_id": "test-client-01", "name": "重复",
        }, headers=AUTH_HEADERS)
        assert resp.status_code == 409

    def test_list_clients(self, client):
        resp = client.get("/api/iam/clients", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

    def test_get_client(self, client):
        resp = client.get("/api/iam/clients/test-client-01", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["client_id"] == "test-client-01"
        assert "client_secret" not in resp.json()

    def test_update_client(self, client):
        resp = client.patch("/api/iam/clients/test-client-01", json={
            "name": "更新后的客户端", "scopes": ["openid", "profile", "roles"],
        }, headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["name"] == "更新后的客户端"
        assert "roles" in resp.json()["scopes"]

    def test_rotate_client_secret(self, client):
        resp = client.post("/api/iam/clients/test-client-01/rotate-secret", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert data["client_id"] == "test-client-01"
        assert "new_client_secret" in data
        assert len(data["new_client_secret"]) > 0

    def test_update_client_status(self, client):
        resp = client.patch("/api/iam/clients/test-client-01/status", json={
            "status": "disabled",
        }, headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["status"] == "disabled"

    def test_delete_client(self, client):
        resp = client.delete("/api/iam/clients/test-client-01", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

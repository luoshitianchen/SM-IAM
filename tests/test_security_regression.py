"""安全回归测试：openapi/docs 关闭。"""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_openapi_schema_disabled(client):
    """/openapi.json 不得暴露 API 结构（信息泄露修复）。"""
    resp = await client.get("/openapi.json")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_docs_ui_disabled(client):
    """/docs 与 /redoc 不得暴露。"""
    assert (await client.get("/docs")).status_code == 404
    assert (await client.get("/redoc")).status_code == 404

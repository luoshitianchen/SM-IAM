"""IAM 客户端服务层：OAuth 客户端全生命周期。"""
from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime

from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import internal_write_allowed, sm3_hex
from app.models.iam_client import IAMClient
from app.repositories import iam_client as repo
from app.schemas.iam_client import ClientCreate, ClientUpdate
from app.services.audit import record_audit


def _client_to_dict(c: IAMClient) -> dict:
    return {
        "client_id": c.client_id, "name": c.name,
        "scopes": json.loads(c.scopes or "[]"),
        "redirect_uris": json.loads(c.redirect_uris or "[]"),
        "status": c.status,
        "created_at": c.created_at.isoformat() if c.created_at else "",
        "rotated_at": c.rotated_at.isoformat() if c.rotated_at else None,
    }


class ClientService:
    @staticmethod
    async def list_clients(session: AsyncSession, limit: int = 100, offset: int = 0,
                            status_filter: str | None = None) -> dict:
        clients = await repo.list_clients(session, limit=limit, offset=offset, status=status_filter)
        total = await repo.count_clients(session)
        return {"total": total, "items": [_client_to_dict(c) for c in clients]}

    @staticmethod
    async def get_client(session: AsyncSession, client_id: str) -> dict:
        client = await repo.get_client(session, client_id)
        if not client:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "客户端不存在")
        return _client_to_dict(client)

    @staticmethod
    async def create_client(session: AsyncSession, payload: ClientCreate, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        if await repo.get_client(session, payload.client_id):
            raise HTTPException(status.HTTP_409_CONFLICT, "client_id 已存在")
        client_secret = secrets.token_urlsafe(32)
        client = IAMClient(
            client_id=payload.client_id, client_secret_hash=sm3_hex(client_secret),
            name=payload.name, scopes=json.dumps(payload.scopes, ensure_ascii=False),
            redirect_uris=json.dumps(payload.redirect_uris, ensure_ascii=False),
            status="active",
        )
        client = await repo.create_client(session, client)
        await record_audit(session, "client.created", "internal",
                           f"client_id={payload.client_id}", request)
        result = _client_to_dict(client)
        result["client_secret"] = client_secret
        return result

    @staticmethod
    async def update_client(session: AsyncSession, client_id: str, payload: ClientUpdate,
                            request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        client = await repo.get_client(session, client_id)
        if not client:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "客户端不存在")
        if payload.name is not None:
            client.name = payload.name
        if payload.scopes is not None:
            client.scopes = json.dumps(payload.scopes, ensure_ascii=False)
        if payload.redirect_uris is not None:
            client.redirect_uris = json.dumps(payload.redirect_uris, ensure_ascii=False)
        client = await repo.update_client(session, client)
        await record_audit(session, "client.updated", "internal",
                           f"client_id={client_id}", request)
        return _client_to_dict(client)

    @staticmethod
    async def update_status(session: AsyncSession, client_id: str, new_status: str,
                             request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        client = await repo.get_client(session, client_id)
        if not client:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "客户端不存在")
        client.status = new_status
        client = await repo.update_client(session, client)
        await record_audit(session, "client.status_changed", "internal",
                           f"client_id={client_id} status={new_status}", request)
        return _client_to_dict(client)

    @staticmethod
    async def rotate_secret(session: AsyncSession, client_id: str, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        client = await repo.get_client(session, client_id)
        if not client:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "客户端不存在")
        new_secret = secrets.token_urlsafe(32)
        client.client_secret_hash = sm3_hex(new_secret)
        client.rotated_at = datetime.now(UTC)
        client = await repo.update_client(session, client)
        await record_audit(session, "client.secret_rotated", "internal",
                           f"client_id={client_id}", request)
        return {
            "client_id": client.client_id,
            "new_client_secret": new_secret,
            "rotated_at": client.rotated_at.isoformat() if client.rotated_at else "",
        }

    @staticmethod
    async def delete_client(session: AsyncSession, client_id: str, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        client = await repo.get_client(session, client_id)
        if not client:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "客户端不存在")
        await repo.delete_client(session, client)
        await record_audit(session, "client.deleted", "internal",
                           f"client_id={client_id}", request)
        return {"deleted": True, "client_id": client_id}

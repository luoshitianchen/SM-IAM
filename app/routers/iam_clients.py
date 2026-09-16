"""IAM 客户端管理路由。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.schemas.iam_client import ClientCreate, ClientStatusUpdate, ClientUpdate
from app.services.iam_client import ClientService

router = APIRouter(prefix="/api/iam/clients", tags=["iam-clients"])


@router.get("")
async def list_clients(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status_filter: str | None = Query(default=None, alias="status"),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await ClientService.list_clients(session, limit=limit, offset=offset,
                                             status_filter=status_filter)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_client(
    payload: ClientCreate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await ClientService.create_client(session, payload, request)


@router.get("/{client_id}")
async def get_client(
    client_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await ClientService.get_client(session, client_id)


@router.patch("/{client_id}")
async def update_client(
    client_id: str, payload: ClientUpdate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await ClientService.update_client(session, client_id, payload, request)


@router.patch("/{client_id}/status")
async def update_client_status(
    client_id: str, payload: ClientStatusUpdate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await ClientService.update_status(session, client_id, payload.status, request)


@router.post("/{client_id}/rotate-secret")
async def rotate_client_secret(
    client_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await ClientService.rotate_secret(session, client_id, request)


@router.delete("/{client_id}")
async def delete_client(
    client_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await ClientService.delete_client(session, client_id, request)

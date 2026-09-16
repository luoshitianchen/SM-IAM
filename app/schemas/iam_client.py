"""IAM 客户端 Pydantic 模型。"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ClientCreate(BaseModel):
    client_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-zA-Z0-9_.-]+$")
    name: str = Field(default="", max_length=128)
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile"])
    redirect_uris: list[str] = Field(default_factory=list)


class ClientUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=128)
    scopes: list[str] | None = None
    redirect_uris: list[str] | None = None


class ClientStatusUpdate(BaseModel):
    status: Literal["active", "disabled"]


class ClientSecretRotateResponse(BaseModel):
    client_id: str
    new_client_secret: str
    rotated_at: datetime


class ClientResponse(BaseModel):
    client_id: str
    name: str
    scopes: list[str]
    redirect_uris: list[str]
    status: str
    created_at: datetime
    rotated_at: datetime | None = None


class ClientListResponse(BaseModel):
    total: int
    items: list[ClientResponse]

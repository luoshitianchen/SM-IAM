"""IAM 角色 Pydantic 模型。"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class RoleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9_:-]+$")
    description: str = Field(default="", max_length=256)
    permissions: list[str] = Field(default_factory=list)


class RoleUpdate(BaseModel):
    description: str | None = Field(default=None, max_length=256)
    permissions: list[str] | None = None


class RoleResponse(BaseModel):
    id: str
    name: str
    description: str
    permissions: list[str]
    is_system: bool
    created_at: datetime


class RoleListResponse(BaseModel):
    total: int
    items: list[RoleResponse]

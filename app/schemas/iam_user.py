"""IAM 用户 Pydantic 模型。"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=128, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=128)
    display_name: str = Field(default="", max_length=128)
    email: str | None = Field(default=None, max_length=256)
    roles: list[str] = Field(default_factory=list)


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=128)
    email: str | None = Field(default=None, max_length=256)
    roles: list[str] | None = None


class UserStatusUpdate(BaseModel):
    status: Literal["active", "disabled", "locked"]


class UserPasswordChange(BaseModel):
    old_password: str
    new_password: str = Field(min_length=8, max_length=128)


class UserResponse(BaseModel):
    id: str
    username: str
    display_name: str
    email: str
    status: str
    roles: list[str]
    failed_login_count: int
    last_login_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class UserListResponse(BaseModel):
    total: int
    items: list[UserResponse]

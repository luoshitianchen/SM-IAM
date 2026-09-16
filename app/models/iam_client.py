"""IAM OAuth 客户端模型。"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.models.base import Base


class IAMClient(Base):
    __tablename__ = "iam_clients"
    client_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    client_secret_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    name: Mapped[str] = mapped_column(String(128), default="")
    scopes: Mapped[str] = mapped_column(Text, default="[]")
    redirect_uris: Mapped[str] = mapped_column(Text, default="[]")
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

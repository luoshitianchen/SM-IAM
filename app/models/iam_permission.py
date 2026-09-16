"""IAM 权限模型。"""
from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class IAMPermission(Base):
    __tablename__ = "iam_permissions"
    code: Mapped[str] = mapped_column(String(128), primary_key=True)
    description: Mapped[str] = mapped_column(String(256), default="")
    resource: Mapped[str] = mapped_column(String(64), default="", index=True)
    action: Mapped[str] = mapped_column(String(32), default="")

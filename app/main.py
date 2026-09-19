"""应用入口：创建 FastAPI 实例并注册中间件与路由。"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse

from app.core.config import settings
from app.core.database import init_db
from app.core.logging import setup_logging
from app.core.middleware import SecurityMiddleware
from app.routers import auth as auth_router
from app.routers import crypto, health, iam_clients, iam_permissions, iam_roles, iam_users, items, meta, metrics

_STATIC_DIR = Path(__file__).resolve().parent / "static"

setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期：启动时初始化数据库，关闭时释放连接。"""
    await init_db()
    yield
    from app.core.database import engine
    await engine.dispose()


app = FastAPI(
    title=settings.DISPLAY_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
app.add_middleware(SecurityMiddleware)

app.include_router(health.router)
app.include_router(meta.router)
app.include_router(crypto.router)
app.include_router(items.router)
app.include_router(metrics.router)
app.include_router(auth_router.router)
app.include_router(iam_users.router)
app.include_router(iam_roles.router)
app.include_router(iam_permissions.router)
app.include_router(iam_clients.router)


@app.get("/", include_in_schema=False)
def console() -> FileResponse:
    """控制台静态页面。"""
    return FileResponse(_STATIC_DIR / "index.html")

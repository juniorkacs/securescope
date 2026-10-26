"""Template setup and helpers shared by the HTML routes."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from app.security import ROLE_RANK, csrf_token

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


def _can(user: Any, role: str) -> bool:
    from app.models import Role

    return user is not None and ROLE_RANK[user.role] >= ROLE_RANK[Role(role)]


def _fmt_date(d: dt.date | None) -> str:
    return d.strftime("%d %b %Y") if d else ""


templates.env.globals.update(can=_can, csrf_token=csrf_token)
templates.env.filters["date"] = _fmt_date


def today(request: Request) -> dt.date:
    fn = request.app.state.today
    result: dt.date = fn()
    return result


def render(request: Request, name: str, status_code: int = 200, **ctx: Any) -> Response:
    ctx.setdefault("demo_mode", request.app.state.settings.demo_mode)
    ctx.setdefault("path", request.url.path)
    response: Response = templates.TemplateResponse(request, name, ctx, status_code=status_code)
    return response

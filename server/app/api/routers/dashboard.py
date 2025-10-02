"""대시보드 및 홈 라우터."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from app.api.dependencies import get_session_service, get_templates
from app.services.session_service import SessionService


router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    session_service: SessionService = Depends(get_session_service),
    templates=Depends(get_templates),
):
    try:
        recent_sessions = session_service.fetch_recent_sessions(10)
        stats = session_service.fetch_stats()
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "recent_sessions": recent_sessions,
                "stats": stats,
            },
        )
    except Exception as exc:  # pragma: no cover
        return HTMLResponse(f"<h1>Dashboard Error</h1><p>{str(exc)}</p>", status_code=500)

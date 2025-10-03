"""세션 관련 라우터 (HTML & REST API)."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from app.api.dependencies import (
    get_session_service,
    get_templates,
    get_analysis_orchestrator,
    get_lstm_analyzer,
)
from app.services.session_service import SessionService
from app.services.analysis.orchestrator import AnalysisOrchestrator
from analysis.integrated_lstm_analyzer import IntegratedLSTMAnalyzer


router = APIRouter()
api_router = APIRouter(prefix="/api/v1")


@router.get("/session/{session_id}", response_class=HTMLResponse)
async def get_session_detail(
    session_id: str,
    request: Request,
    session_service: SessionService = Depends(get_session_service),
    templates=Depends(get_templates),
):
    session = session_service.fetch_session_detail(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    files = session.get("vulnerability_results", []) + session.get("malicious_results", [])
    return templates.TemplateResponse(
        "session_detail.html",
        {
            "request": request,
            "session": session,
            "files": files,
        },
    )


@router.get("/session/{session_id}/malicious", response_class=HTMLResponse)
async def get_malicious_files(
    session_id: str,
    request: Request,
    session_service: SessionService = Depends(get_session_service),
    templates=Depends(get_templates),
):
    session = session_service.fetch_session_detail(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return templates.TemplateResponse(
        "malicious_view.html",
        {
            "request": request,
            "session": session,
            "malicious_files": session.get("malicious_results", []),
            "malicious_safe_files": session.get("malicious_safe_results", []),
        },
    )


@router.get("/session/{session_id}/vulnerable", response_class=HTMLResponse)
async def get_vulnerable_files(
    session_id: str,
    request: Request,
    session_service: SessionService = Depends(get_session_service),
    templates=Depends(get_templates),
):
    session = session_service.fetch_session_detail(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return templates.TemplateResponse(
        "vulnerable_view.html",
        {
            "request": request,
            "session": session,
            "vulnerable_files": session.get("vulnerability_results", []),
            "vulnerable_safe_files": session.get("vulnerability_safe_results", []),
        },
    )


@router.get("/session/{session_id}/ML", response_class=HTMLResponse)
async def get_ml_results(
    session_id: str,
    request: Request,
    session_service: SessionService = Depends(get_session_service),
    templates=Depends(get_templates),
):
    session = session_service.fetch_session_detail(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    ml_results = session_service.fetch_ml_analysis(session_id)
    ml_summary = session_service.fetch_ml_summary(session_id)

    return templates.TemplateResponse(
        "ml_analysis_view.html",
        {
            "request": request,
            "session": session,
            "results": ml_results,
            "summary": ml_summary,
        },
    )


@api_router.get("/sessions")
async def get_sessions(
    skip: int = 0,
    limit: int = 100,
    session_service: SessionService = Depends(get_session_service),
):
    sessions = session_service.fetch_recent_sessions(limit)
    return sessions[skip : skip + limit]


@api_router.get("/sessions/{session_id}")
async def get_session(session_id: str, session_service: SessionService = Depends(get_session_service)):
    session = session_service.fetch_session_detail(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@api_router.get("/stats")
async def get_stats(
    session_service: SessionService = Depends(get_session_service),
    orchestrator: AnalysisOrchestrator = Depends(get_analysis_orchestrator),
    lstm_analyzer: IntegratedLSTMAnalyzer = Depends(get_lstm_analyzer),
):
    try:
        stats = session_service.fetch_stats()
    except Exception:
        stats = {
            "total_sessions": 0,
            "total_files": 0,
            "malicious_files": 0,
            "vulnerable_files": 0,
            "safe_files": 0,
            "malicious_rate": 0,
            "vulnerable_rate": 0,
            "safe_rate": 0,
        }
    stats["multiprocess_active_tasks"] = lstm_analyzer.get_active_tasks_count()
    return stats


@api_router.get("/multiprocess/status")
async def get_multiprocess_status(lstm_analyzer: IntegratedLSTMAnalyzer = Depends(get_lstm_analyzer)):
    return {
        "active_tasks": lstm_analyzer.get_active_tasks_count(),
        "max_workers": 3,
        "status": "running" if lstm_analyzer.get_active_tasks_count() > 0 else "idle",
        "timestamp": datetime.utcnow().isoformat(),
    }

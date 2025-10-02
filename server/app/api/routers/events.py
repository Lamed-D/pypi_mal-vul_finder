"""SSE 이벤트 스트림 라우터."""

from fastapi import APIRouter, Depends, Request

from app.api.dependencies import get_analysis_orchestrator
from app.services.analysis.orchestrator import AnalysisOrchestrator


router = APIRouter(prefix="/api/v1")


@router.get("/events/{session_id}")
async def stream_session_events(
    session_id: str,
    request: Request,
    orchestrator: AnalysisOrchestrator = Depends(get_analysis_orchestrator),
):
    return await orchestrator.stream_events(session_id, request)

"""파일 업로드와 분석 트리거 라우터."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.api.dependencies import (
    get_analysis_orchestrator,
    get_file_service,
)
from app.services.analysis.orchestrator import AnalysisOrchestrator
from app.services.file_service import FileService


router = APIRouter()
api_router = APIRouter(prefix="/api/v1")


async def _process_upload(
    upload: UploadFile,
    orchestrator: AnalysisOrchestrator,
    file_service: FileService,
    model: str,
    mode: str | None = None,
) -> dict:
    if not upload.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    suffix = Path(upload.filename).suffix.lower()
    if suffix not in settings.allowed_extension_set:
        raise HTTPException(status_code=400, detail="Only ZIP files are allowed")

    content = await upload.read()
    if len(content) > settings.max_file_size:
        raise HTTPException(status_code=400, detail="File too large")

    session_id = str(uuid.uuid4())
    file_path = file_service.save_uploaded_file(content, session_id, upload.filename)

    if model == "lstm":
        task = orchestrator.analyze_lstm(session_id, file_path, upload.filename, len(content), mode or "both")
    elif model == "bert":
        task = orchestrator.analyze_bert(session_id, file_path, upload.filename, len(content), mode or "both")
    elif model == "ml":
        task = orchestrator.analyze_ml(session_id, file_path, upload.filename, len(content))
    else:  # pragma: no cover - 방어 코드
        raise HTTPException(status_code=400, detail=f"Unsupported model: {model}")

    asyncio.create_task(task)
    await orchestrator.publish_started(session_id, upload.filename, model, mode)

    return {
        "session_id": session_id,
        "filename": upload.filename,
        "model": model,
        "mode": mode,
    }


@router.post("/upload")
async def upload_file_simple(
    file: UploadFile = File(...),
    orchestrator: AnalysisOrchestrator = Depends(get_analysis_orchestrator),
    file_service: FileService = Depends(get_file_service),
):
    """VS Code 확장에서 사용하는 간단 업로드 엔드포인트."""
    result = await _process_upload(file, orchestrator, file_service, model="lstm", mode="both")
    dashboard_url = f"http://{settings.host}:{settings.port}/session/{result['session_id']}"
    return {
        "message": "File uploaded successfully",
        "session_id": result["session_id"],
        "status": "processing",
        "dashboard_url": dashboard_url,
    }


@api_router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    orchestrator: AnalysisOrchestrator = Depends(get_analysis_orchestrator),
    file_service: FileService = Depends(get_file_service),
):
    result = await _process_upload(file, orchestrator, file_service, model="lstm", mode="both")
    return JSONResponse(
        {
            "session_id": result["session_id"],
            "filename": result["filename"],
            "status": "uploaded",
            "message": "File uploaded successfully. Analysis started.",
        }
    )


@api_router.post("/upload/lstm")
async def upload_file_lstm_both(
    file: UploadFile = File(...),
    orchestrator: AnalysisOrchestrator = Depends(get_analysis_orchestrator),
    file_service: FileService = Depends(get_file_service),
):
    result = await _process_upload(file, orchestrator, file_service, model="lstm", mode="both")
    return JSONResponse(
        {
            "session_id": result["session_id"],
            "filename": result["filename"],
            "status": "uploaded",
            "mode": "both",
            "message": "File uploaded successfully. LSTM analysis (both vulnerability and malicious) started.",
        }
    )


@api_router.post("/upload/lstm/mal")
async def upload_file_lstm_malicious(
    file: UploadFile = File(...),
    orchestrator: AnalysisOrchestrator = Depends(get_analysis_orchestrator),
    file_service: FileService = Depends(get_file_service),
):
    result = await _process_upload(file, orchestrator, file_service, model="lstm", mode="mal")
    return JSONResponse(
        {
            "session_id": result["session_id"],
            "filename": result["filename"],
            "status": "uploaded",
            "mode": "malicious",
            "message": "File uploaded successfully. LSTM malicious code analysis started.",
        }
    )


@api_router.post("/upload/lstm/vul")
async def upload_file_lstm_vulnerability(
    file: UploadFile = File(...),
    orchestrator: AnalysisOrchestrator = Depends(get_analysis_orchestrator),
    file_service: FileService = Depends(get_file_service),
):
    result = await _process_upload(file, orchestrator, file_service, model="lstm", mode="vul")
    return JSONResponse(
        {
            "session_id": result["session_id"],
            "filename": result["filename"],
            "status": "uploaded",
            "mode": "vulnerability",
            "message": "File uploaded successfully. LSTM vulnerability analysis started.",
        }
    )


@api_router.post("/upload/bert")
async def upload_file_bert_both(
    file: UploadFile = File(...),
    orchestrator: AnalysisOrchestrator = Depends(get_analysis_orchestrator),
    file_service: FileService = Depends(get_file_service),
):
    result = await _process_upload(file, orchestrator, file_service, model="bert", mode="both")
    return JSONResponse(
        {
            "session_id": result["session_id"],
            "filename": result["filename"],
            "status": "uploaded",
            "mode": "both",
            "message": "File uploaded successfully. BERT analysis (both vulnerability and malicious) started.",
        }
    )


@api_router.post("/upload/bert/mal")
async def upload_file_bert_malicious(
    file: UploadFile = File(...),
    orchestrator: AnalysisOrchestrator = Depends(get_analysis_orchestrator),
    file_service: FileService = Depends(get_file_service),
):
    result = await _process_upload(file, orchestrator, file_service, model="bert", mode="mal")
    return JSONResponse(
        {
            "session_id": result["session_id"],
            "filename": result["filename"],
            "status": "uploaded",
            "mode": "malicious",
            "message": "File uploaded successfully. BERT malicious code analysis started.",
        }
    )


@api_router.post("/upload/bert/vul")
async def upload_file_bert_vulnerability(
    file: UploadFile = File(...),
    orchestrator: AnalysisOrchestrator = Depends(get_analysis_orchestrator),
    file_service: FileService = Depends(get_file_service),
):
    result = await _process_upload(file, orchestrator, file_service, model="bert", mode="vul")
    return JSONResponse(
        {
            "session_id": result["session_id"],
            "filename": result["filename"],
            "status": "uploaded",
            "mode": "vulnerability",
            "message": "File uploaded successfully. BERT vulnerability analysis started.",
        }
    )


@api_router.post("/upload/ML")
async def upload_file_ml(
    file: UploadFile = File(...),
    orchestrator: AnalysisOrchestrator = Depends(get_analysis_orchestrator),
    file_service: FileService = Depends(get_file_service),
):
    result = await _process_upload(file, orchestrator, file_service, model="ml")
    return JSONResponse(
        {
            "session_id": result["session_id"],
            "filename": result["filename"],
            "status": "uploaded",
            "message": "File uploaded successfully. ML analysis (LSTM + XGBoost) started.",
        }
    )

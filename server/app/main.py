"""
Python Security Analysis System - 메인 애플리케이션
====================================================

이 모듈은 Python 코드의 보안 분석을 위한 FastAPI 웹 애플리케이션의 메인 진입점입니다.

주요 기능:
- ZIP 파일 업로드 및 Python 파일 추출
- AI 기반 취약점 및 악성코드 탐지
- 웹 인터페이스를 통한 분석 결과 표시
- RESTful API를 통한 데이터 제공

작동 방식:
1. 사용자가 ZIP 파일을 업로드
2. ZIP에서 Python 파일만 추출하여 메모리에 로드
3. LSTM AI 모델로 취약점/악성코드 분석
4. 결과를 데이터베이스에 저장하고 웹에 표시
"""

import sys
import os
from pathlib import Path

# 서버 디렉토리를 Python 경로에 추가 (모듈 import를 위해)
server_dir = Path(__file__).parents[1]
sys.path.insert(0, str(server_dir))

# FastAPI 및 웹 관련 라이브러리
from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

# 유틸리티 라이브러리
import uuid
import asyncio
from datetime import datetime
from typing import Optional

# 내부 모듈 import
from database.database import (
    init_database, save_analysis_results, get_session_summary, get_stats, get_recent_sessions,
    save_pkg_vul_analysis_results, get_pkg_vul_analysis_by_session, get_pkg_vul_analysis_summary,
    save_ml_analysis_log
)
from analysis.integrated_lstm_analyzer import IntegratedLSTMAnalyzer
from analysis.bert_analyzer import BERTAnalyzer
from analysis.ml_package_analyzer import MLPackageAnalyzer
from app.services.file_service import FileService
from app.services.event_service import EventManager
from config import UPLOAD_DIR, MAX_FILE_SIZE, ALLOWED_EXTENSIONS

# =============================================================================
# FastAPI 애플리케이션 초기화
# =============================================================================

# FastAPI 앱 인스턴스 생성
app = FastAPI(
    title="PySecure - Python Security Analysis System",
    description="AI-powered Python code security analysis with vulnerability and malware detection using LSTM, BERT, and ML models",
    version="2.0.0"
)

# 정적 파일 서빙은 CDN을 통해 제공 (Bootstrap, Prism.js 등)

# HTML 템플릿 엔진 설정 (Jinja2)
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# 템플릿에 JSON 필터 추가 (JavaScript에서 안전한 데이터 전달을 위해)
import json
templates.env.filters["tojson"] = json.dumps

# =============================================================================
# 서비스 및 컴포넌트 초기화
# =============================================================================

# 데이터베이스 초기화 (테이블 생성 및 연결 설정)
init_database()

# 파일 처리 서비스 초기화 (ZIP 압축 해제, 파일 검증 등)
file_service = FileService()

# 통합 LSTM 분석기 초기화 (취약점 + 악성코드 탐지)
models_dir = str((Path(__file__).parents[1] / "models").resolve())
integrated_analyzer = IntegratedLSTMAnalyzer(models_dir)

# BERT 분석기 초기화
bert_analyzer = BERTAnalyzer(models_dir)

# ML 패키지 분석기 초기화 (LSTM + XGBoost)
ml_package_analyzer = MLPackageAnalyzer()

# SSE 이벤트 매니저 초기화
event_manager = EventManager()

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    print("🚀 Starting PySecure - Python Security Analysis System...")
    print("📊 Database initialized")
    print("🧠 AI Models loaded (LSTM, BERT, ML)")
    print("✅ Services ready")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    print("🛑 Shutting down PySecure...")
    if integrated_analyzer:
        integrated_analyzer.shutdown_executor()
    if bert_analyzer:
        bert_analyzer.shutdown_executor()
    print("✅ Shutdown complete")

# =============================================================================
# 웹 페이지 라우트
# =============================================================================

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """
    메인 대시보드 페이지
    
    기능:
    - 최근 분석 세션 목록 표시
    - 전체 분석 통계 정보 표시
    - 파일 업로드 인터페이스 제공
    
    Returns:
        HTMLResponse: 대시보드 HTML 페이지
    """
    try:
        # 최근 분석 세션 10개 조회 (데이터베이스에서)
        recent_sessions = get_recent_sessions(10)
        
        # 전체 분석 통계 조회 (데이터베이스에서)
        from database.database import get_stats as get_db_stats
        stats = get_db_stats()
        
        # 디버그 정보 출력 (개발 중에만 사용)
        print(f"DEBUG: stats type: {type(stats)}")
        print(f"DEBUG: stats content: {stats}")
        
        # 대시보드 템플릿 렌더링 및 반환
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "recent_sessions": recent_sessions,
            "stats": stats
        })
    except Exception as e:
        print(f"Dashboard error: {e}")
        import traceback
        traceback.print_exc()
        # 오류 발생 시 간단한 오류 페이지 반환
        return HTMLResponse(f"<h1>Dashboard Error</h1><p>{str(e)}</p>")

@app.post("/upload")
async def upload_file_simple(
    file: UploadFile = File(...)
):
    """
    간단한 파일 업로드 엔드포인트 (VS Code 확장용)
    
    기능:
    - ZIP 파일 업로드 및 검증
    - 세션 ID 생성
    - 백그라운드에서 AI 분석 시작
    
    Args:
        file (UploadFile): 업로드된 ZIP 파일
        
    Returns:
        dict: 업로드 성공 정보 및 세션 ID
    """
    try:
        # 파일명 검증
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided")
        
        # 파일 확장자 검증 (ZIP 파일만 허용)
        file_extension = Path(file.filename).suffix.lower()
        if file_extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=400, detail="Only ZIP files are allowed")
        
        # 파일 크기 검증
        file_content = await file.read()
        if len(file_content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File too large")
        
        # 고유 세션 ID 생성
        session_id = str(uuid.uuid4())
        
        # 파일을 서버에 저장
        file_path = file_service.save_uploaded_file(file_content, session_id, file.filename)
        
        # 분석 완료 후 통합 데이터베이스에 세션 생성됨
        
        # 백그라운드에서 통합 다중 프로세스 분석 시작
        asyncio.create_task(analyze_file_integrated_async(session_id, str(file_path), file.filename, len(file_content)))
        await _publish_started(session_id, file.filename, "lstm", "both")

        return {
            "message": "File uploaded successfully",
            "session_id": session_id,
            "status": "processing",
            "dashboard_url": f"http://127.0.0.1:8000/session/{session_id}"
        }
        
    except Exception as e:
        print(f"❌ Upload error: {str(e)}")
        print(f"❌ Error type: {type(e).__name__}")
        import traceback
        print("❌ Full traceback:")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.post("/api/v1/upload")
async def upload_file(
    file: UploadFile = File(...)
):
    """Upload ZIP file for analysis"""
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided")
        
        file_extension = Path(file.filename).suffix.lower()
        if file_extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=400, detail="Only ZIP files are allowed")
        
        # Check file size
        file_content = await file.read()
        if len(file_content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File too large")
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Save file
        file_path = file_service.save_uploaded_file(file_content, session_id, file.filename)
        
        # Session will be created in integrated database after analysis
        
        # Start integrated multiprocess analysis in background (both mode)
        asyncio.create_task(analyze_file_integrated_async(session_id, str(file_path), file.filename, len(file_content), "both"))
        await _publish_started(session_id, file.filename, "lstm", "both")

        return JSONResponse({
            "session_id": session_id,
            "filename": file.filename,
            "status": "uploaded",
            "message": "File uploaded successfully. Analysis started."
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/upload/lstm")
async def upload_file_lstm_both(
    file: UploadFile = File(...)
):
    """Upload ZIP file for LSTM analysis (both vulnerability and malicious)"""
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided")
        
        file_extension = Path(file.filename).suffix.lower()
        if file_extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=400, detail="Only ZIP files are allowed")
        
        # Check file size
        file_content = await file.read()
        if len(file_content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File too large")
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Save file
        file_path = file_service.save_uploaded_file(file_content, session_id, file.filename)
        
        # Start integrated multiprocess analysis in background (both mode)
        asyncio.create_task(analyze_file_integrated_async(session_id, str(file_path), file.filename, len(file_content), "both"))
        await _publish_started(session_id, file.filename, "lstm", "both")

        return JSONResponse({
            "session_id": session_id,
            "filename": file.filename,
            "status": "uploaded",
            "mode": "both",
            "message": "File uploaded successfully. LSTM analysis (both vulnerability and malicious) started."
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/upload/lstm/mal")
async def upload_file_lstm_malicious(
    file: UploadFile = File(...)
):
    """Upload ZIP file for LSTM malicious code analysis only"""
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided")
        
        file_extension = Path(file.filename).suffix.lower()
        if file_extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=400, detail="Only ZIP files are allowed")
        
        # Check file size
        file_content = await file.read()
        if len(file_content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File too large")
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Save file
        file_path = file_service.save_uploaded_file(file_content, session_id, file.filename)
        
        # Start integrated multiprocess analysis in background (malicious only)
        asyncio.create_task(analyze_file_integrated_async(session_id, str(file_path), file.filename, len(file_content), "mal"))
        await _publish_started(session_id, file.filename, "lstm", "mal")

        return JSONResponse({
            "session_id": session_id,
            "filename": file.filename,
            "status": "uploaded",
            "mode": "malicious",
            "message": "File uploaded successfully. LSTM malicious code analysis started."
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/upload/lstm/vul")
async def upload_file_lstm_vulnerability(
    file: UploadFile = File(...)
):
    """Upload ZIP file for LSTM vulnerability analysis only"""
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided")
        
        file_extension = Path(file.filename).suffix.lower()
        if file_extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=400, detail="Only ZIP files are allowed")
        
        # Check file size
        file_content = await file.read()
        if len(file_content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File too large")
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Save file
        file_path = file_service.save_uploaded_file(file_content, session_id, file.filename)
        
        # Start integrated multiprocess analysis in background (vulnerability only)
        asyncio.create_task(analyze_file_integrated_async(session_id, str(file_path), file.filename, len(file_content), "vul"))
        await _publish_started(session_id, file.filename, "lstm", "vul")

        return JSONResponse({
            "session_id": session_id,
            "filename": file.filename,
            "status": "uploaded",
            "mode": "vulnerability",
            "message": "File uploaded successfully. LSTM vulnerability analysis started."
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/upload/bert")
async def upload_file_bert_both(
    file: UploadFile = File(...)
):
    """Upload ZIP file for BERT analysis (both vulnerability and malicious)"""
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided")
        
        file_extension = Path(file.filename).suffix.lower()
        if file_extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=400, detail="Only ZIP files are allowed")
        
        # Check file size
        file_content = await file.read()
        if len(file_content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File too large")
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Save file
        file_path = file_service.save_uploaded_file(file_content, session_id, file.filename)
        
        # Start BERT analysis in background (both mode)
        asyncio.create_task(analyze_file_bert_async(session_id, str(file_path), file.filename, len(file_content), "both"))
        await _publish_started(session_id, file.filename, "bert", "both")

        return JSONResponse({
            "session_id": session_id,
            "filename": file.filename,
            "status": "uploaded",
            "mode": "both",
            "message": "File uploaded successfully. BERT analysis (both vulnerability and malicious) started."
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/upload/bert/mal")
async def upload_file_bert_malicious(
    file: UploadFile = File(...)
):
    """Upload ZIP file for BERT malicious code analysis only"""
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided")
        
        file_extension = Path(file.filename).suffix.lower()
        if file_extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=400, detail="Only ZIP files are allowed")
        
        # Check file size
        file_content = await file.read()
        if len(file_content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File too large")
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Save file
        file_path = file_service.save_uploaded_file(file_content, session_id, file.filename)
        
        # Start BERT analysis in background (malicious only)
        asyncio.create_task(analyze_file_bert_async(session_id, str(file_path), file.filename, len(file_content), "mal"))
        await _publish_started(session_id, file.filename, "bert", "mal")

        return JSONResponse({
            "session_id": session_id,
            "filename": file.filename,
            "status": "uploaded",
            "mode": "malicious",
            "message": "File uploaded successfully. BERT malicious code analysis started."
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/upload/bert/vul")
async def upload_file_bert_vulnerability(
    file: UploadFile = File(...)
):
    """Upload ZIP file for BERT vulnerability analysis only"""
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided")
        
        file_extension = Path(file.filename).suffix.lower()
        if file_extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=400, detail="Only ZIP files are allowed")
        
        # Check file size
        file_content = await file.read()
        if len(file_content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File too large")
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Save file
        file_path = file_service.save_uploaded_file(file_content, session_id, file.filename)
        
        # Start BERT analysis in background (vulnerability only)
        asyncio.create_task(analyze_file_bert_async(session_id, str(file_path), file.filename, len(file_content), "vul"))
        await _publish_started(session_id, file.filename, "bert", "vul")

        return JSONResponse({
            "session_id": session_id,
            "filename": file.filename,
            "status": "uploaded",
            "mode": "vulnerability",
            "message": "File uploaded successfully. BERT vulnerability analysis started."
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def analyze_file_integrated_async(session_id: str, file_path: str, filename: str, file_size: int, mode: str = "both"):
    """통합 다중 프로세스 백그라운드 분석 작업 - ZIP → .py 추출 → 병렬 분석 → DB 저장
    
    Args:
        session_id: 세션 ID
        file_path: 파일 경로
        filename: 파일명
        file_size: 파일 크기
        mode: 'both' | 'mal' | 'vul'
    """
    try:
        print(f"🚀 Starting integrated multiprocess analysis for session {session_id}")
        print(f"📦 Processing ZIP file: {filename} ({file_size} bytes)")
        
        # 1. ZIP 파일에서 Python 파일들만 추출 (.py 확장자만, 나머지 파일 제거)
        extracted_files = await file_service.extract_zip_file(file_path)
        print(f"📁 Extracted {len(extracted_files)} Python files from {filename} (non-Python files filtered out)")
        
        if not extracted_files:
            print(f"⚠️ No Python files found in {filename}")
            # 빈 결과로 main_log에 기록
            upload_info = {
                "upload_time": datetime.now(),
                "filename": filename,
                "file_size": file_size
            }
            save_result = save_analysis_results(session_id, [], upload_info, mode, is_bert=False)
            await event_manager.publish(
                session_id,
                "analysis_complete",
                {
                    "session_id": session_id,
                    "model": "lstm",
                    "mode": mode,
                    "filename": filename,
                    "status": "completed",
                    "summary": {
                        "total_files": save_result["total_files"],
                        "safe_files": save_result["safe_files"],
                        "vulnerable_files": save_result["vulnerability_results"],
                        "malicious_files": save_result["malicious_results"],
                        "analysis_time": save_result["total_analysis_time"]
                    },
                    "redirect_url": f"/session/{session_id}"
                }
            )
            return
        
        # 2. 통합 다중 프로세스 분석 실행 (3개 프로세스 제한)
        print(f"🔍 Starting multiprocess analysis with 3 workers for {len(extracted_files)} files (mode: {mode})")
        analysis_result = await integrated_analyzer.analyze_files_multiprocess(session_id, extracted_files, mode)
        
        if analysis_result["status"] == "completed":
            # 3. 결과를 분리된 DB 테이블에 저장
            upload_info = {
                "upload_time": datetime.now(),
                "filename": filename,
                "file_size": file_size
            }
            
            save_result = save_analysis_results(
                session_id, 
                analysis_result["results"], 
                upload_info,
                mode,
                is_bert=False  # LSTM 분석
            )
            
            print(f"✅ Integrated analysis completed for session {session_id}")
            print(f"📊 Results: {save_result['vulnerability_results']} vulnerable, {save_result['malicious_results']} malicious, {save_result['safe_files']} safe")
            print(f"⏱️ Total analysis time: {save_result['total_analysis_time']:.2f} seconds")
            print(f"💾 Results saved to: LSTM_VUL, LSTM_MAL, main_log tables")
            print(f"🔄 Server continues running for next analysis...")

            await event_manager.publish(
                session_id,
                "analysis_complete",
                {
                    "session_id": session_id,
                    "model": "lstm",
                    "mode": mode,
                    "filename": filename,
                    "status": "completed",
                    "summary": {
                        "total_files": save_result["total_files"],
                        "safe_files": save_result["safe_files"],
                        "vulnerable_files": save_result["vulnerability_results"],
                        "malicious_files": save_result["malicious_results"],
                        "analysis_time": save_result["total_analysis_time"]
                    },
                    "redirect_url": f"/session/{session_id}"
                }
            )
            
        else:
            print(f"❌ Integrated analysis failed for session {session_id}: {analysis_result.get('error', 'Unknown error')}")
            await event_manager.publish(
                session_id,
                "analysis_failed",
                {
                    "session_id": session_id,
                    "model": "lstm",
                    "mode": mode,
                    "filename": filename,
                    "status": "failed",
                    "error": analysis_result.get("error", "Unknown error")
                }
            )

    except Exception as e:
        print(f"❌ Integrated analysis failed for session {session_id}: {e}")
        import traceback
        traceback.print_exc()
        print(f"🔄 Server continues running despite analysis error...")
        await event_manager.publish(
            session_id,
            "analysis_failed",
            {
                "session_id": session_id,
                "model": "lstm",
                "mode": mode,
                "filename": filename,
                "status": "failed",
                "error": str(e)
            }
        )

async def analyze_file_bert_async(session_id: str, file_path: str, filename: str, file_size: int, mode: str = "both"):
    """BERT 백그라운드 분석 작업 - ZIP → .py 추출 → BERT 분석 → DB 저장
    
    Args:
        session_id: 세션 ID
        file_path: 파일 경로
        filename: 파일명
        file_size: 파일 크기
        mode: 'both' | 'mal' | 'vul'
    """
    try:
        print(f"🚀 Starting BERT analysis for session {session_id}")
        print(f"📦 Processing ZIP file: {filename} ({file_size} bytes)")
        
        # 1. ZIP 파일에서 Python 파일들만 추출 (.py 확장자만, 나머지 파일 제거)
        extracted_files = await file_service.extract_zip_file(file_path)
        print(f"📁 Extracted {len(extracted_files)} Python files from {filename} (non-Python files filtered out)")
        
        if not extracted_files:
            print(f"⚠️ No Python files found in {filename}")
            # 빈 결과로 main_log에 기록
            upload_info = {
                "upload_time": datetime.now(),
                "filename": filename,
                "file_size": file_size
            }
            save_result = save_analysis_results(session_id, [], upload_info, mode, is_bert=True)
            await event_manager.publish(
                session_id,
                "analysis_complete",
                {
                    "session_id": session_id,
                    "model": "bert",
                    "mode": mode,
                    "filename": filename,
                    "status": "completed",
                    "summary": {
                        "total_files": save_result["total_files"],
                        "safe_files": save_result["safe_files"],
                        "vulnerable_files": save_result["vulnerability_results"],
                        "malicious_files": save_result["malicious_results"],
                        "analysis_time": save_result["total_analysis_time"]
                    },
                    "redirect_url": f"/session/{session_id}"
                }
            )
            return
        
        # 2. BERT 분석 실행
        print(f"🔍 Starting BERT analysis for {len(extracted_files)} files (mode: {mode})")
        analysis_result = await bert_analyzer.analyze_files_multiprocess(session_id, extracted_files, mode)
        
        if analysis_result["status"] == "completed":
            # 3. 결과를 BERT DB 테이블에 저장
            upload_info = {
                "upload_time": datetime.now(),
                "filename": filename,
                "file_size": file_size
            }
            
            save_result = save_analysis_results(
                session_id, 
                analysis_result["results"], 
                upload_info,
                mode,
                is_bert=True
            )
            
            print(f"✅ BERT analysis completed for session {session_id}")
            print(f"📊 Results: {save_result['vulnerability_results']} vulnerable, {save_result['malicious_results']} malicious, {save_result['safe_files']} safe")
            print(f"⏱️ Total analysis time: {save_result['total_analysis_time']:.2f} seconds")
            print(f"💾 Results saved to: BERT_VUL, BERT_MAL, main_log tables")
            print(f"🔄 Server continues running for next analysis...")
            await event_manager.publish(
                session_id,
                "analysis_complete",
                {
                    "session_id": session_id,
                    "model": "bert",
                    "mode": mode,
                    "filename": filename,
                    "status": "completed",
                    "summary": {
                        "total_files": save_result["total_files"],
                        "safe_files": save_result["safe_files"],
                        "vulnerable_files": save_result["vulnerability_results"],
                        "malicious_files": save_result["malicious_results"],
                        "analysis_time": save_result["total_analysis_time"]
                    },
                    "redirect_url": f"/session/{session_id}"
                }
            )
            
        else:
            print(f"❌ BERT analysis failed for session {session_id}: {analysis_result.get('error', 'Unknown error')}")
            await event_manager.publish(
                session_id,
                "analysis_failed",
                {
                    "session_id": session_id,
                    "model": "bert",
                    "mode": mode,
                    "filename": filename,
                    "status": "failed",
                    "error": analysis_result.get("error", "Unknown error")
                }
            )

    except Exception as e:
        print(f"❌ BERT analysis failed for session {session_id}: {e}")
        import traceback
        traceback.print_exc()
        print(f"🔄 Server continues running despite analysis error...")
        await event_manager.publish(
            session_id,
            "analysis_failed",
            {
                "session_id": session_id,
                "model": "bert",
                "mode": mode,
                "filename": filename,
                "status": "failed",
                "error": str(e)
            }
        )


@app.get("/session/{session_id}")
async def get_session_detail(session_id: str, request: Request):
    """Get detailed session information from integrated database"""
    try:
        # 통합 DB에서 세션 정보 조회
        session_summary = get_session_summary(session_id)
        
        if not session_summary:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return templates.TemplateResponse("session_detail.html", {
            "request": request,
            "session": session_summary,
            "files": session_summary.get("vulnerability_results", []) + session_summary.get("malicious_results", [])
        })
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error getting session detail: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/session/{session_id}/malicious")
async def get_malicious_files(session_id: str, request: Request):
    """악성 코드 분석 결과만 보여주는 페이지"""
    try:
        # 통합 DB에서 세션 정보 조회
        session_summary = get_session_summary(session_id)
        
        if not session_summary:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return templates.TemplateResponse("malicious_view.html", {
            "request": request,
            "session": session_summary,
            "malicious_files": session_summary.get("malicious_results", []),
            "malicious_safe_files": session_summary.get("malicious_safe_results", [])
        })
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error getting malicious files: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/session/{session_id}/vulnerable")
async def get_vulnerable_files(session_id: str, request: Request):
    """취약점 분석 결과만 보여주는 페이지"""
    try:
        # 통합 DB에서 세션 정보 조회
        session_summary = get_session_summary(session_id)
        
        if not session_summary:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return templates.TemplateResponse("vulnerable_view.html", {
            "request": request,
            "session": session_summary,
            "vulnerable_files": session_summary.get("vulnerability_results", []),
            "vulnerable_safe_files": session_summary.get("vulnerability_safe_results", [])
        })
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error getting vulnerable files: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def _format_sse_message(payload: dict) -> str:
    """Format SSE message with event name and JSON payload."""
    event_name = payload.get("event", "message")
    data = json.dumps(payload.get("data", {}))
    return f"event: {event_name}\n" f"data: {data}\n\n"


@app.get("/api/v1/events/{session_id}")
async def stream_session_events(session_id: str, request: Request):
    """SSE endpoint streaming analysis updates for a session."""
    queue = await event_manager.subscribe(session_id)

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue

                yield _format_sse_message(event)

        finally:
            await event_manager.unsubscribe(session_id, queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


async def _publish_started(session_id: str, filename: str, model: str, mode: Optional[str] = None) -> None:
    """Notify subscribers that an analysis session has started."""
    data = {
        "session_id": session_id,
        "filename": filename,
        "status": "processing",
        "model": model
    }
    if mode:
        data["mode"] = mode
    await event_manager.publish(session_id, "analysis_started", data)


@app.get("/api/v1/sessions")
async def get_sessions(skip: int = 0, limit: int = 100):
    """Get analysis sessions from integrated database"""
    sessions = get_recent_sessions(limit)
    return sessions[skip:skip + limit]

@app.get("/api/v1/sessions/{session_id}")
async def get_session(session_id: str):
    """Get specific analysis session with files from integrated database"""
    session_summary = get_session_summary(session_id)
    if not session_summary:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return session_summary

@app.get("/api/v1/stats")
async def get_stats():
    """Get analysis statistics from integrated database"""
    try:
        # 통합 DB에서 통계 조회
        from database.database import get_stats as get_db_stats
        stats = get_db_stats()
        stats["multiprocess_active_tasks"] = integrated_analyzer.get_active_tasks_count()
        return stats
        
    except Exception as e:
        print(f"❌ Error getting stats: {e}")
        return {
            "total_sessions": 0,
            "total_files": 0,
            "malicious_files": 0,
            "vulnerable_files": 0,
            "safe_files": 0,
            "malicious_rate": 0,
            "vulnerable_rate": 0,
            "safe_rate": 0,
            "multiprocess_active_tasks": integrated_analyzer.get_active_tasks_count()
        }

@app.get("/api/v1/multiprocess/status")
async def get_multiprocess_status():
    """Get multiprocess analysis status"""
    return {
        "active_tasks": integrated_analyzer.get_active_tasks_count(),
        "max_workers": 3,
        "status": "running" if integrated_analyzer.get_active_tasks_count() > 0 else "idle"
    }

@app.get("/api/v1/source/{session_id}/{file_path:path}")
async def get_source_code(session_id: str, file_path: str):
    """
    세션 ID 기반 소스코드 조회
    
    Args:
        session_id (str): 분석 세션 ID
        file_path (str): 파일 경로
        
    Returns:
        PlainTextResponse: 소스코드 내용
    """
    try:
        print(f"🔍 Requesting source code for session: {session_id}, file: {file_path}")
        print(f"🔍 UPLOAD_DIR: {UPLOAD_DIR}")
        
        # 파일 경로 정규화 (백슬래시를 슬래시로 변환)
        normalized_file_path = file_path.replace('\\', '/')
        print(f"🔍 Normalized file path: {normalized_file_path}")
        
        # 세션 디렉토리 확인
        upload_dir = UPLOAD_DIR / session_id
        print(f"🔍 Looking for session directory: {upload_dir}")
        print(f"🔍 Directory exists: {upload_dir.exists()}")
        
        if not upload_dir.exists():
            print(f"❌ Session directory not found: {upload_dir}")
            # 사용 가능한 세션 디렉토리 목록 출력
            available_sessions = [d.name for d in UPLOAD_DIR.iterdir() if d.is_dir()]
            print(f"🔍 Available sessions: {available_sessions}")
            raise HTTPException(status_code=404, detail="Session not found")
        
        # extracted 디렉토리에서 검색
        search_dirs = [upload_dir / "extracted"]
        print(f"🔍 Search directory: {search_dirs[0]}")
        print(f"🔍 Search directory exists: {search_dirs[0].exists()}")
        
        file_full_path = None
        
        # 파일 검색
        for extract_dir in search_dirs:
            print(f"🔍 Searching in: {extract_dir}")
            
            # 파일 경로 파싱
            path_parts = normalized_file_path.split('/')
            filename = path_parts[-1]
            
            print(f"🔍 Original filename: {filename}")
            print(f"🔍 Normalized file path: {normalized_file_path}")
            
            # 여러 가능한 경로 시도
            possible_paths = [
                extract_dir / normalized_file_path, # 정규화된 전체 경로
                extract_dir / file_path,            # 원본 전체 경로
                extract_dir / filename,             # 파일명만
            ]
            
            # 파일명으로 검색 (원본)
            matching_files = list(extract_dir.rglob(f"*{filename}"))
            if matching_files:
                possible_paths.extend(matching_files)
            
            # 정확한 파일명으로도 검색
            exact_files = list(extract_dir.rglob(filename))
            if exact_files:
                possible_paths.extend(exact_files)
            
            # 중복 제거
            possible_paths = list(set(possible_paths))
            
            print(f"🔍 Possible paths to check: {len(possible_paths)}")
            for i, path in enumerate(possible_paths[:10]):  # 처음 10개만 로그
                print(f"  {i+1}. {path}")
            
            for path in possible_paths:
                if path.exists() and path.is_file():
                    file_full_path = path
                    break
            
            if file_full_path:
                break
        
        if not file_full_path:
            # 디렉토리 내용 확인
            print(f"🔍 Available files in search directories:")
            for search_dir in search_dirs:
                if search_dir.exists():
                    print(f"  Directory: {search_dir}")
                    for item in search_dir.rglob("*.py"):
                        print(f"    - {item}")
            raise HTTPException(status_code=404, detail=f"File not found: {file_path}")
        
        print(f"🔍 Found file at: {file_full_path}")
        
        # 파일 내용 읽기
        try:
            with open(file_full_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            # UTF-8로 읽기 실패 시 다른 인코딩 시도
            with open(file_full_path, 'r', encoding='latin-1') as f:
                content = f.read()
        
        print(f"✅ Successfully loaded source code for {file_full_path.name}")
        # 순수 텍스트로 반환 (JSON 직렬화 방지)
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(content)
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error getting source code: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/test")
async def test_endpoint():
    """Test endpoint to check if server is working"""
    try:
        from database.database import get_stats as get_db_stats
        stats = get_db_stats()
        return {
            "status": "ok",
            "service": "PySecure",
            "version": "2.0.0",
            "stats": stats,
            "message": "PySecure server is working correctly"
        }
    except Exception as e:
        return {
            "status": "error",
            "service": "PySecure",
            "error": str(e),
            "message": "PySecure server has issues"
        }

@app.get("/health")
async def health_check():
    """Health check endpoint to keep server alive"""
    return {
        "status": "healthy",
        "service": "PySecure",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat(),
        "active_tasks": integrated_analyzer.get_active_tasks_count(),
        "message": "PySecure server is running and ready for analysis"
        }

# =============================================================================
# ML 패키지 분석 엔드포인트
# =============================================================================

@app.post("/api/v1/upload/ML")
async def upload_file_ml(file: UploadFile = File(...)):
    """Upload ZIP file for ML analysis (LSTM + XGBoost)"""
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided")
        
        file_extension = Path(file.filename).suffix.lower()
        if file_extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=400, detail="Only ZIP files are allowed")
        
        # Check file size
        file_content = await file.read()
        if len(file_content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File too large")
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Save file using file_service (same as other endpoints)
        file_path = file_service.save_uploaded_file(file_content, session_id, file.filename)
        
        # Start ML analysis in background
        asyncio.create_task(analyze_file_ml_async(session_id, str(file_path), file.filename, len(file_content)))
        await _publish_started(session_id, file.filename, "ml")

        return JSONResponse({
            "session_id": session_id,
            "filename": file.filename,
            "status": "uploaded",
            "message": "File uploaded successfully. ML analysis (LSTM + XGBoost) started."
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def analyze_file_ml_async(session_id: str, file_path: str, filename: str, file_size: int):
    """ML 백그라운드 분석 작업 - ZIP → .py 추출 → ML 분석 → DB 저장
    
    Args:
        session_id: 세션 ID
        file_path: 파일 경로
        filename: 파일명
        file_size: 파일 크기
    """
    try:
        print(f"🔍 ML 분석 시작: {filename} (Session: {session_id})")
        
        # 파일 추출 (기존 패턴과 동일)
        extracted_files = await file_service.extract_zip_file(file_path)
        
        if not extracted_files:
            print(f"❌ 파일 추출 실패: {session_id}")
            await event_manager.publish(
                session_id,
                "analysis_failed",
                {
                    "session_id": session_id,
                    "model": "ml",
                    "filename": filename,
                    "status": "failed",
                    "error": "No Python files found in archive"
                }
            )
            return

        # ML 패키지 분석 수행 (추출된 파일들을 직접 사용)
        extract_dir = UPLOAD_DIR / session_id / "extracted"
        analysis_result = await asyncio.to_thread(
            ml_package_analyzer.analyze_extracted_files,
            str(extract_dir),
            extracted_files
        )

        if "error" in analysis_result:
            print(f"❌ ML 분석 실패: {analysis_result['error']}")
            await event_manager.publish(
                session_id,
                "analysis_failed",
                {
                    "session_id": session_id,
                    "model": "ml",
                    "filename": filename,
                    "status": "failed",
                    "error": analysis_result["error"]
                }
            )
            return

        # 분석 결과를 DB에 저장
        if analysis_result.get("success") and analysis_result.get("results"):
            # 결과 데이터 준비
            db_results = []
            for result in analysis_result["results"]:
                db_result = {
                    "package_name": result.get("name", ""),
                    "summary": result.get("summary", ""),
                    "author": result.get("author", ""),
                    "author_email": result.get("author-email", ""),
                    "version": result.get("version", ""),
                    "download_count": result.get("download", 0),
                    "lstm_vulnerability_status": result.get("lstm_vulnerability_status", ""),
                    "lstm_cwe_label": result.get("lstm_cwe_label", ""),
                    "lstm_confidence": result.get("lstm_confidence", 0.0),
                    "xgboost_prediction": result.get("xgboost_prediction", 0),
                    "xgboost_confidence": result.get("xgboost_confidence", 0.0),
                    "final_malicious_status": bool(result.get("xgboost_prediction", 0)),
                    "threat_level": 2 if result.get("xgboost_prediction", 0) == 1 else 0,
                    "analysis_time": analysis_result.get("analysis_time", 0.0)
                }
                db_results.append(db_result)
            
            # PKG_VUL_ANALYSIS 테이블에 저장
            save_pkg_vul_analysis_results(session_id, db_results)
            
            # main_log에 저장
            upload_info = {
                "upload_time": datetime.utcnow(),
                "filename": filename,
                "file_size": file_size
            }
            save_ml_analysis_log(session_id, upload_info, db_results, analysis_result.get("analysis_time", 0.0))

        print(f"✅ ML 분석 완료: {filename} (Session: {session_id})")
        summary_data = analysis_result.get("summary") or {}
        total_packages = analysis_result.get("total_packages", len(analysis_result.get("results", [])))
        await event_manager.publish(
            session_id,
            "analysis_complete",
            {
                "session_id": session_id,
                "model": "ml",
                "filename": filename,
                "status": "completed",
                "summary": {
                    "total_packages": total_packages,
                    "malicious_packages": summary_data.get("malicious_packages", 0),
                    "vulnerable_packages": summary_data.get("vulnerable_packages", 0),
                    "safe_packages": summary_data.get("safe_packages", 0),
                    "analysis_time": analysis_result.get("analysis_time", 0.0)
                },
                "redirect_url": f"/session/{session_id}/ML"
            }
        )

    except Exception as e:
        print(f"❌ ML 분석 중 오류: {e}")
        import traceback
        traceback.print_exc()
        await event_manager.publish(
            session_id,
            "analysis_failed",
            {
                "session_id": session_id,
                "model": "ml",
                "filename": filename,
                "status": "failed",
                "error": str(e)
            }
        )

@app.get("/api/v1/sessions/ML/{session_id}")
async def get_ml_analysis_results(session_id: str):
    """
    ML 패키지 분석 결과 조회
    
    Args:
        session_id: 분석 세션 ID
        
    Returns:
        JSON: 분석 결과 상세 정보
    """
    try:
        # DB에서 분석 결과 조회
        results = get_pkg_vul_analysis_by_session(session_id)
        summary = get_pkg_vul_analysis_summary(session_id)
        
        if not results:
            raise HTTPException(status_code=404, detail="분석 결과를 찾을 수 없습니다.")
        
        return {
            "session_id": session_id,
            "summary": summary,
            "results": results,
            "total_packages": len(results),
            "status": "success"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ ML 분석 결과 조회 중 오류: {e}")
        raise HTTPException(status_code=500, detail=f"결과 조회 중 오류가 발생했습니다: {str(e)}")

@app.get("/api/v1/sessions/ML/{session_id}/summary")
async def get_ml_analysis_summary(session_id: str):
    """
    ML 패키지 분석 결과 요약 조회
    
    Args:
        session_id: 분석 세션 ID
        
    Returns:
        JSON: 분석 결과 요약 정보
    """
    try:
        summary = get_pkg_vul_analysis_summary(session_id)
        
        if summary["total_packages"] == 0:
            raise HTTPException(status_code=404, detail="분석 결과를 찾을 수 없습니다.")
        
        return {
            "session_id": session_id,
            "summary": summary,
            "status": "success"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ ML 분석 요약 조회 중 오류: {e}")
        raise HTTPException(status_code=500, detail=f"요약 조회 중 오류가 발생했습니다: {str(e)}")

@app.get("/session/{session_id}/ML", response_class=HTMLResponse)
async def ml_analysis_view(session_id: str, request: Request):
    """
    ML 패키지 분석 결과 웹 페이지
    
    Args:
        session_id: 분석 세션 ID
        
    Returns:
        HTML: 분석 결과 웹 페이지
    """
    try:
        # DB에서 분석 결과 조회
        results = get_pkg_vul_analysis_by_session(session_id)
        summary = get_pkg_vul_analysis_summary(session_id)
        
        if not results:
            return templates.TemplateResponse("error.html", {
                "request": request,
                "error_title": "분석 결과를 찾을 수 없습니다",
                "error_message": f"세션 ID '{session_id}'에 대한 분석 결과가 존재하지 않습니다.",
                "error_code": 404
            })
        
        return templates.TemplateResponse("ml_analysis_view.html", {
            "request": request,
            "session_id": session_id,
            "results": results,
            "summary": summary,
            "total_packages": len(results)
        })
        
    except Exception as e:
        print(f"❌ ML 분석 결과 페이지 로드 중 오류: {e}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error_title": "페이지 로드 오류",
            "error_message": f"분석 결과를 불러오는 중 오류가 발생했습니다: {str(e)}",
            "error_code": 500
        })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

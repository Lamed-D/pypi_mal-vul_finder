"""
FastAPI 메인 애플리케이션 - ZIP → .py 추출 → 다중 프로세스 분석
"""
import sys
import os
from pathlib import Path

# Add server directory to Python path
server_dir = Path(__file__).parents[1]
sys.path.insert(0, str(server_dir))

from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
import uuid
import asyncio
from datetime import datetime

from database.database import init_database, save_analysis_results, get_session_summary, get_stats, get_recent_sessions
from analysis.integrated_lstm_analyzer import IntegratedLSTMAnalyzer
from app.services.file_service import FileService
from config import UPLOAD_DIR, MAX_FILE_SIZE, ALLOWED_EXTENSIONS

# Initialize FastAPI app
app = FastAPI(
    title="Python Security Analysis System",
    description="AI-powered Python code security analysis with vulnerability and malware detection",
    version="1.0.0"
)

# Mount static files
static_dir = Path(__file__).parents[1] / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Templates
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# Initialize integrated database
init_database()

# Initialize services
file_service = FileService()

# Initialize integrated LSTM analyzer (vulnerability + malicious)
models_dir = str((Path(__file__).parents[1] / "models").resolve())
integrated_analyzer = IntegratedLSTMAnalyzer(models_dir)

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    print("Starting Python Security Analysis System...")
    print("Database initialized")
    print("Services ready")

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Main dashboard page"""
    try:
        # Get recent analysis sessions from integrated database
        recent_sessions = get_recent_sessions(10)
        
        # Get statistics from integrated database
        from database.database import get_stats as get_db_stats
        stats = get_db_stats()
        
        print(f"DEBUG: stats type: {type(stats)}")
        print(f"DEBUG: stats content: {stats}")
        
        return templates.TemplateResponse("dashboard.html", {
            "request": {},
            "recent_sessions": recent_sessions,
            "stats": stats
        })
    except Exception as e:
        print(f"Dashboard error: {e}")
        import traceback
        traceback.print_exc()
        # Return simple error page
        return HTMLResponse(f"<h1>Dashboard Error</h1><p>{str(e)}</p>")

@app.post("/upload")
async def upload_file_simple(
    file: UploadFile = File(...)
):
    """Simple upload endpoint for VS Code extension"""
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
        
        # Start integrated multiprocess analysis in background
        asyncio.create_task(analyze_file_integrated_async(session_id, str(file_path), file.filename, len(file_content)))
        
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
        
        # Start integrated multiprocess analysis in background
        asyncio.create_task(analyze_file_integrated_async(session_id, str(file_path), file.filename, len(file_content)))
        
        return JSONResponse({
            "session_id": session_id,
            "filename": file.filename,
            "status": "uploaded",
            "message": "File uploaded successfully. Analysis started."
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def analyze_file_integrated_async(session_id: str, file_path: str, filename: str, file_size: int):
    """통합 다중 프로세스 백그라운드 분석 작업 - ZIP → .py 추출 → 병렬 분석 → DB 저장"""
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
            save_analysis_results(session_id, [], upload_info)
            return
        
        # 2. 통합 다중 프로세스 분석 실행 (3개 프로세스 제한)
        print(f"🔍 Starting multiprocess analysis with 3 workers for {len(extracted_files)} files")
        analysis_result = await integrated_analyzer.analyze_files_multiprocess(session_id, extracted_files)
        
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
                upload_info
            )
            
            print(f"✅ Integrated analysis completed for session {session_id}")
            print(f"📊 Results: {save_result['vulnerability_results']} vulnerable, {save_result['malicious_results']} malicious, {save_result['safe_files']} safe")
            print(f"⏱️ Total analysis time: {save_result['total_analysis_time']:.2f} seconds")
            print(f"💾 Results saved to: LSTM_VUL, LSTM_MAL, main_log tables")
            
        else:
            print(f"❌ Integrated analysis failed for session {session_id}: {analysis_result.get('error', 'Unknown error')}")
        
    except Exception as e:
        print(f"❌ Integrated analysis failed for session {session_id}: {e}")
        import traceback
        traceback.print_exc()


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
            "malicious_files": session_summary.get("malicious_results", [])
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
            "vulnerable_files": session_summary.get("vulnerability_results", [])
        })
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error getting vulnerable files: {e}")
        raise HTTPException(status_code=500, detail=str(e))

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

@app.get("/test")
async def test_endpoint():
    """Test endpoint to check if server is working"""
    try:
        from database.database import get_stats as get_db_stats
        stats = get_db_stats()
        return {
            "status": "ok",
            "stats": stats,
            "message": "Server is working correctly"
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "message": "Server has issues"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
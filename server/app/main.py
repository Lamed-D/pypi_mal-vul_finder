"""
FastAPI main application for Python Security Analysis System
"""
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
import uuid
import os
import asyncio
from datetime import datetime
from pathlib import Path

from database.database import get_db, AnalysisSession, AnalyzedFile, AnalysisLog, init_database
from analysis.lstm_analyzer import LSTMAnalyzer
from app.services.file_service import FileService
from app.services.analysis_service import AnalysisService
from config import UPLOAD_DIR, MAX_FILE_SIZE, ALLOWED_EXTENSIONS

# Initialize FastAPI app
app = FastAPI(
    title="Python Security Analysis System",
    description="AI-powered Python code security analysis with vulnerability and malware detection",
    version="1.0.0"
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="app/templates")

# Initialize database
init_database()

# Initialize services
file_service = FileService()
analysis_service = AnalysisService()
# Initialize LSTM analyzer (malicious-only minimal pipeline)
lstm_model_path = str((Path(__file__).parents[1] / "models" / "lstm" / "model_mal.pkl").resolve())
w2v_path = str((Path(__file__).parents[1] / "models" / "w2v" / "word2vec_withString10-6-100.model").resolve())
lstm_analyzer = LSTMAnalyzer(lstm_model_path, w2v_path)

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    print("Starting Python Security Analysis System...")
    print("Database initialized")
    print("Services ready")

@app.get("/", response_class=HTMLResponse)
async def dashboard(db: Session = Depends(get_db)):
    """Main dashboard page"""
    # Get recent analysis sessions
    recent_sessions = db.query(AnalysisSession).order_by(AnalysisSession.upload_time.desc()).limit(10).all()
    
    # Get statistics
    total_sessions = db.query(AnalysisSession).count()
    total_files = db.query(AnalyzedFile).count()
    malicious_files = db.query(AnalyzedFile).filter(AnalyzedFile.is_malicious == True).count()
    vulnerable_files = db.query(AnalyzedFile).filter(AnalyzedFile.is_vulnerable == True).count()
    
    stats = {
        "total_sessions": total_sessions,
        "total_files": total_files,
        "malicious_files": malicious_files,
        "vulnerable_files": vulnerable_files
    }
    
    return templates.TemplateResponse("dashboard.html", {
        "request": {},
        "recent_sessions": recent_sessions,
        "stats": stats
    })

@app.post("/upload")
async def upload_file_simple(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
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
        
        # Create analysis session
        session = AnalysisSession(
            id=session_id,
            filename=file.filename,
            file_size=len(file_content),
            upload_time=datetime.now(),
            status="processing"
        )
        db.add(session)
        db.commit()
        
        # Start analysis in background (LSTM-only)
        asyncio.create_task(analyze_file_async(session_id, str(file_path), db))
        
        return {
            "message": "File uploaded successfully",
            "session_id": session_id,
            "status": "processing",
            "dashboard_url": f"http://127.0.0.1:8000/session/{session_id}"
        }
        
    except Exception as e:
        db.rollback()
        print(f"❌ Upload error: {str(e)}")
        print(f"❌ Error type: {type(e).__name__}")
        import traceback
        print("❌ Full traceback:")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.post("/api/v1/upload")
async def upload_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
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
        
        # Create analysis session
        session = AnalysisSession(
            session_id=session_id,
            filename=file.filename,
            file_size=len(file_content),
            status="pending"
        )
        db.add(session)
        db.commit()
        
        # Start analysis in background
        asyncio.create_task(analyze_file_async(session_id, file_path, db))
        
        return JSONResponse({
            "session_id": session_id,
            "filename": file.filename,
            "status": "uploaded",
            "message": "File uploaded successfully. Analysis started."
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def analyze_file_async(session_id: str, file_path: str, db: Session):
    """Background analysis task"""
    try:
        # Update session status
        session = db.query(AnalysisSession).filter(AnalysisSession.session_id == session_id).first()
        session.status = "processing"
        db.commit()
        
        # Extract and analyze files
        extracted_files = await file_service.extract_zip_file(file_path)
        session.total_files = len(extracted_files)
        db.commit()
        
        # Analyze each file with LSTM only
        processed_count = 0
        for file_info in extracted_files:
            try:
                # Only analyze Python files
                if not file_info["path"].endswith('.py'):
                    continue
                mal_result = lstm_analyzer.analyze_mal(file_info["content"])
                
                analyzed_file = AnalyzedFile(
                    session_id=session_id,
                    file_path=file_info["path"],
                    file_name=file_info["name"],
                    file_size=file_info["size"],
                    is_malicious=mal_result.get("is_malicious", False),
                    malicious_probability=mal_result.get("malicious_probability", 0.0),
                    lstm_label=mal_result.get("lstm_label"),
                    lstm_probability=mal_result.get("lstm_probability"),
                    analysis_time=mal_result.get("analysis_time", 0.0),
                    analysis_method="lstm"
                )
                db.add(analyzed_file)
                processed_count += 1
                session.processed_files = processed_count
                db.commit()
            except Exception as e:
                print(f"Error analyzing file {file_info['path']}: {e}")
                continue
        
        # Mark session as completed
        session.status = "completed"
        db.commit()
        
    except Exception as e:
        # Mark session as failed
        session = db.query(AnalysisSession).filter(AnalysisSession.session_id == session_id).first()
        session.status = "failed"
        session.error_message = str(e)
        db.commit()
        print(f"Analysis failed for session {session_id}: {e}")

@app.get("/session/{session_id}")
async def get_session_detail(session_id: str, db: Session = Depends(get_db)):
    """Get detailed session information"""
    session = db.query(AnalysisSession).filter(AnalysisSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    files = db.query(AnalyzedFile).filter(AnalyzedFile.session_id == session_id).all()
    
    return templates.TemplateResponse("session_detail.html", {
        "request": {},
        "session": session,
        "files": files
    })

@app.get("/api/v1/sessions")
async def get_sessions(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get analysis sessions"""
    sessions = db.query(AnalysisSession).offset(skip).limit(limit).all()
    return sessions

@app.get("/api/v1/sessions/{session_id}")
async def get_session(session_id: str, db: Session = Depends(get_db)):
    """Get specific analysis session with files"""
    session = db.query(AnalysisSession).filter(AnalysisSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    files = db.query(AnalyzedFile).filter(AnalyzedFile.session_id == session_id).all()
    
    return {
        "session": session,
        "files": files
    }

@app.get("/api/v1/stats")
async def get_stats(db: Session = Depends(get_db)):
    """Get analysis statistics"""
    total_sessions = db.query(AnalysisSession).count()
    total_files = db.query(AnalyzedFile).count()
    malicious_files = db.query(AnalyzedFile).filter(AnalyzedFile.is_malicious == True).count()
    vulnerable_files = db.query(AnalyzedFile).filter(AnalyzedFile.is_vulnerable == True).count()
    
    return {
        "total_sessions": total_sessions,
        "total_files": total_files,
        "malicious_files": malicious_files,
        "vulnerable_files": vulnerable_files,
        "malicious_rate": (malicious_files / total_files * 100) if total_files > 0 else 0,
        "vulnerable_rate": (vulnerable_files / total_files * 100) if total_files > 0 else 0
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

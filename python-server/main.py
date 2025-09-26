from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
import shutil
import tempfile
from pathlib import Path
import os

app = FastAPI()

@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    if not file:
        raise HTTPException(status_code=400, detail="No file uploaded")

    # Ensure persistent uploads directory exists alongside this file
    base_dir = Path(__file__).resolve().parent
    uploads_dir = base_dir / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)

    saved_name = file.filename or "uploaded.zip"
    saved_path = uploads_dir / saved_name

    with open(saved_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    def iterfile():
        with open(tmp_path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                yield chunk

    def cleanup() -> None:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            if os.path.isdir(tmp_dir):
                os.rmdir(tmp_dir)
        except Exception:
            pass

    # 서버에 파일을 남기고 메타데이터 JSON 반환
    size = os.path.getsize(saved_path)
    return JSONResponse({
        "filename": saved_name,
        "size": size,
        "saved_path": str(saved_path)
    })



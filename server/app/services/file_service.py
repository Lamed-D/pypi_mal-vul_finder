"""
파일 처리 서비스 - ZIP → .py 파일만 추출 (나머지 파일 제거)
"""
import os
import zipfile
import tempfile
from pathlib import Path
from typing import List, Dict, Any
import uuid

from config import UPLOAD_DIR

class FileService:
    def __init__(self):
        self.upload_dir = UPLOAD_DIR
        self.upload_dir.mkdir(exist_ok=True)
    
    def save_uploaded_file(self, file_content: bytes, session_id: str, filename: str) -> str:
        """업로드된 파일을 디스크에 저장"""
        # 세션 디렉토리 생성
        session_dir = self.upload_dir / session_id
        session_dir.mkdir(exist_ok=True)
        
        # 파일 저장
        file_path = session_dir / filename
        with open(file_path, 'wb') as f:
            f.write(file_content)
        
        return str(file_path)
    
    async def extract_zip_file(self, zip_path: str) -> List[Dict[str, Any]]:
        """ZIP 파일에서 .py 파일만 추출 (나머지 파일 제거)"""
        files = []
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for file_info in zip_ref.infolist():
                    # .py 확장자 파일만 처리 (__pycache__ 제외)
                    if (file_info.filename.endswith('.py') and 
                        not file_info.filename.startswith('__pycache__') and
                        not file_info.filename.startswith('.')):
                        try:
                            content = zip_ref.read(file_info.filename).decode('utf-8')
                            files.append({
                                "path": file_info.filename,
                                "name": Path(file_info.filename).name,
                                "content": content,
                                "size": len(content)
                            })
                        except Exception as e:
                            print(f"❌ Error reading file {file_info.filename}: {e}")
                            continue
        except Exception as e:
            print(f"❌ Error extracting ZIP file: {e}")
            raise e
        
        print(f"✅ Extracted {len(files)} Python files from ZIP (non-Python files filtered out)")
        return files
    
    def cleanup_session_files(self, session_id: str):
        """세션 파일들 정리"""
        session_dir = self.upload_dir / session_id
        if session_dir.exists():
            import shutil
            shutil.rmtree(session_dir)
    
    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """파일 정보 조회"""
        path = Path(file_path)
        return {
            "name": path.name,
            "size": path.stat().st_size if path.exists() else 0,
            "extension": path.suffix,
            "exists": path.exists()
        }

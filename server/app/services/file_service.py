"""
File handling service for ZIP uploads and extraction
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
        """Save uploaded file to disk"""
        # Create session directory
        session_dir = self.upload_dir / session_id
        session_dir.mkdir(exist_ok=True)
        
        # Save file
        file_path = session_dir / filename
        with open(file_path, 'wb') as f:
            f.write(file_content)
        
        return str(file_path)
    
    async def extract_zip_file(self, zip_path: str) -> List[Dict[str, Any]]:
        """Extract ZIP file and return list of files"""
        files = []
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for file_info in zip_ref.infolist():
                    # Only process Python files and metadata files
                    if (file_info.filename.endswith('.py') or 
                        file_info.filename.endswith('.txt') or
                        file_info.filename.endswith('.json')):
                        
                        try:
                            content = zip_ref.read(file_info.filename).decode('utf-8')
                            files.append({
                                "path": file_info.filename,
                                "name": Path(file_info.filename).name,
                                "content": content,
                                "size": len(content)
                            })
                        except Exception as e:
                            print(f"Error reading file {file_info.filename}: {e}")
                            continue
        except Exception as e:
            print(f"Error extracting ZIP file: {e}")
            raise e
        
        return files
    
    def cleanup_session_files(self, session_id: str):
        """Clean up files for a session"""
        session_dir = self.upload_dir / session_id
        if session_dir.exists():
            import shutil
            shutil.rmtree(session_dir)
    
    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get file information"""
        path = Path(file_path)
        return {
            "name": path.name,
            "size": path.stat().st_size if path.exists() else 0,
            "extension": path.suffix,
            "exists": path.exists()
        }

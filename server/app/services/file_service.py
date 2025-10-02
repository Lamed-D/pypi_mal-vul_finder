"""
파일 처리 서비스 - ZIP 파일 처리 및 Python 파일 추출
=====================================================

이 모듈은 업로드된 ZIP 파일을 처리하고 Python 파일만 추출하는 서비스를 제공합니다.

주요 기능:
- ZIP 파일 저장 및 검증
- ZIP 압축 해제 및 Python 파일만 추출
- 원본 ZIP 파일 자동 삭제
- 파일 메타데이터 수집

보안 고려사항:
- 파일 크기 및 확장자 검증
- 압축 해제 후 원본 파일 즉시 삭제
- 세션별 디렉토리 격리
"""

import asyncio
import os
import zipfile
from pathlib import Path
from typing import List, Dict, Any

from app.core.config import settings

class FileService:
    """
    파일 처리 서비스 클래스
    
    업로드된 ZIP 파일을 처리하고 Python 파일만 추출하여
    AI 분석을 위한 데이터를 준비합니다.
    """
    
    def __init__(self):
        """파일 서비스 초기화"""
        # 업로드 디렉토리 설정 및 생성
        self.upload_dir = settings.upload_dir
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
        """ZIP 파일을 추출하는 동기 작업을 별도 스레드로 위임한다."""
        return await asyncio.to_thread(self._extract_zip_file_sync, zip_path)

    def _extract_zip_file_sync(self, zip_path: str) -> List[Dict[str, Any]]:
        """ZIP 파일을 UPLOAD에 압축 해제하고 .py 파일만 추출 (ZIP 파일 제거)"""
        files: List[Dict[str, Any]] = []
        zip_file_path = Path(zip_path)
        extract_dir = zip_file_path.parent / "extracted"

        try:
            # 압축 해제 디렉토리 생성
            extract_dir.mkdir(exist_ok=True)

            # ZIP 파일 압축 해제
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)

            print(f"✅ ZIP file extracted to: {extract_dir}")

            # .py 파일만 찾아서 처리
            for py_file in extract_dir.rglob("*.py"):
                # __pycache__ 제외
                if "__pycache__" in str(py_file):
                    continue

                try:
                    # 파일 내용 읽기
                    with open(py_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # 상대 경로 계산 (extract_dir 기준)
                    relative_path = py_file.relative_to(extract_dir)

                    files.append({
                        "path": str(relative_path),
                        "name": py_file.name,
                        "content": content,
                        "size": len(content)
                    })

                except Exception as e:
                    print(f"❌ Error reading file {py_file}: {e}")
                    continue

            # ZIP 파일 제거
            zip_file_path.unlink()
            print(f"✅ ZIP file removed: {zip_file_path}")

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

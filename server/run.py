"""
Python Security Analysis System - 서버 실행 스크립트
==================================================

이 모듈은 Python Security Analysis System의 메인 진입점입니다.

주요 기능:
- 데이터베이스 초기화
- Uvicorn ASGI 서버 시작
- 개발 모드 자동 리로드

실행 방법:
    python run.py

서버 접속:
    http://127.0.0.1:8000
"""

import uvicorn
import os
import sys
from pathlib import Path

# 서버 디렉토리를 Python 경로에 추가 (모듈 import를 위해)
server_dir = Path(__file__).parent
sys.path.insert(0, str(server_dir))

# 설정 및 데이터베이스 모듈 import
from config import HOST, PORT, LOG_LEVEL
from database.database import init_database

def main():
    """
    보안 분석 서버 시작
    
    서버 시작 전에 데이터베이스를 초기화하고
    Uvicorn ASGI 서버를 시작합니다.
    """
    # 서버 시작 정보 출력
    print("=" * 60)
    print("Python Security Analysis System")
    print("=" * 60)
    print(f"Server starting on http://{HOST}:{PORT}")
    print(f"Log level: {LOG_LEVEL}")
    print("=" * 60)
    
    # 데이터베이스 초기화
    print("Initializing database...")
    init_database()
    print("Database initialized successfully")
    
    # Uvicorn ASGI 서버 시작
    uvicorn.run(
        "app.main:app",           # FastAPI 앱 모듈 경로
        host=HOST,                # 서버 호스트
        port=PORT,                # 서버 포트
        log_level=LOG_LEVEL.lower(),  # 로그 레벨
        reload=False,             # 자동 리로드 비활성화 (서버 안정성)
        access_log=True,          # 접근 로그 활성화
        loop="asyncio"            # 이벤트 루프 명시적 설정
    )

if __name__ == "__main__":
    main()

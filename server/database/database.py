"""
통합 데이터베이스 - ZIP → .py 추출 → 다중 프로세스 분석 → 분리된 테이블 저장
- LSTM_VUL: 취약점 분석 결과 (safepy_3)
- LSTM_MAL: 악성 코드 분석 결과 (safepy_3_malicious)  
- main_log: 안전한 파일 요약 로그
"""
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime
from typing import Dict, Any, List, Optional
import os

# 데이터베이스 파일 경로 - main.db로 변경
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "main.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

# SQLAlchemy 설정
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class LSTM_VUL(Base):
    """취약점 분석 결과 테이블 (safepy_3)"""
    __tablename__ = "lstm_vul"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    file_path = Column(String)
    file_name = Column(String)
    file_size = Column(Integer)
    vulnerability_status = Column(String)  # "Vulnerable" or "Benign"
    vulnerability_probability = Column(Float)
    vulnerability_label = Column(String)
    cwe_label = Column(String)
    analysis_time = Column(Float)
    upload_time = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

class LSTM_MAL(Base):
    """악성 코드 분석 결과 테이블 (safepy_3_malicious)"""
    __tablename__ = "lstm_mal"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    file_path = Column(String)
    file_name = Column(String)
    file_size = Column(Integer)
    malicious_status = Column(String)  # "malicious" or "benign"
    malicious_probability = Column(Float)
    malicious_label = Column(String)
    analysis_time = Column(Float)
    upload_time = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

class main_log(Base):
    """안전한 파일 요약 로그 테이블"""
    __tablename__ = "main_log"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    upload_time = Column(DateTime, default=datetime.utcnow)
    filename = Column(String)
    file_size = Column(Integer)
    analysis_model = Column(String, default="Integrated LSTM")
    analysis_duration = Column(Float)
    total_files = Column(Integer)
    safe_files = Column(Integer)
    vulnerable_files = Column(Integer)
    malicious_files = Column(Integer)
    is_safe = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

def init_database():
    """통합 데이터베이스 초기화"""
    try:
        # 모든 테이블 생성
        Base.metadata.create_all(bind=engine)
        print("✅ Integrated database initialized successfully")
        print(f"📁 Database file: {DB_PATH}")
        print("📊 Tables created: lstm_vul, lstm_mal, main_log")
    except Exception as e:
        print(f"❌ Error initializing integrated database: {e}")

def get_db() -> Session:
    """데이터베이스 세션 반환"""
    db = SessionLocal()
    try:
        return db
    finally:
        pass

def save_analysis_results(session_id: str, results: List[Dict[str, Any]], upload_info: Dict[str, Any]) -> Dict[str, Any]:
    """분석 결과를 통합 데이터베이스에 저장"""
    db = get_db()
    try:
        vulnerability_results = 0
        malicious_results = 0
        safe_files = 0
        total_analysis_time = 0.0
        
        for result in results:
            # 분석 시간 누적
            total_analysis_time += result.get("analysis_time", 0.0)
            
            # 취약점 분석 결과 저장
            vul_analysis = result.get("vulnerability_analysis", {})
            if vul_analysis.get("is_vulnerable", False):
                vulnerability_results += 1
                vul_record = LSTM_VUL(
                    session_id=session_id,
                    file_path=result.get("file_path", ""),
                    file_name=result.get("file_name", ""),
                    file_size=result.get("file_size", 0),
                    vulnerability_status=vul_analysis.get("vulnerability_status", "Vulnerable"),
                    vulnerability_probability=vul_analysis.get("vulnerability_probability", 0.0),
                    vulnerability_label=vul_analysis.get("vulnerability_label", ""),
                    cwe_label=vul_analysis.get("cwe_label", ""),
                    analysis_time=result.get("analysis_time", 0.0),
                    upload_time=upload_info.get("upload_time", datetime.utcnow())
                )
                db.add(vul_record)
            
            # 악성 코드 분석 결과 저장
            mal_analysis = result.get("malicious_analysis", {})
            if mal_analysis.get("is_malicious", False):
                malicious_results += 1
                mal_record = LSTM_MAL(
                    session_id=session_id,
                    file_path=result.get("file_path", ""),
                    file_name=result.get("file_name", ""),
                    file_size=result.get("file_size", 0),
                    malicious_status=mal_analysis.get("malicious_status", "malicious"),
                    malicious_probability=mal_analysis.get("malicious_probability", 0.0),
                    malicious_label=mal_analysis.get("malicious_label", ""),
                    analysis_time=result.get("analysis_time", 0.0),
                    upload_time=upload_info.get("upload_time", datetime.utcnow())
                )
                db.add(mal_record)
            
            # 안전한 파일 카운트
            if result.get("is_safe", False):
                safe_files += 1
        
        # main_log에 요약 저장
        total_files = len(results)
        is_safe = (vulnerability_results == 0 and malicious_results == 0)
        
        log_record = main_log(
            session_id=session_id,
            upload_time=upload_info.get("upload_time", datetime.utcnow()),
            filename=upload_info.get("filename", ""),
            file_size=upload_info.get("file_size", 0),
            analysis_model="Integrated LSTM",
            analysis_duration=total_analysis_time,
            total_files=total_files,
            safe_files=safe_files,
            vulnerable_files=vulnerability_results,
            malicious_files=malicious_results,
            is_safe=is_safe
        )
        db.add(log_record)
        
        db.commit()
        
        return {
            "session_id": session_id,
            "total_files": total_files,
            "vulnerability_results": vulnerability_results,
            "malicious_results": malicious_results,
            "safe_files": safe_files,
            "total_analysis_time": total_analysis_time,
            "is_safe": is_safe
        }
        
    except Exception as e:
        db.rollback()
        print(f"❌ Error saving analysis results: {e}")
        raise e
    finally:
        db.close()

def get_session_summary(session_id: str) -> Optional[Dict[str, Any]]:
    """세션 요약 정보 조회"""
    db = get_db()
    try:
        # main_log에서 기본 정보 조회
        log_record = db.query(main_log).filter(main_log.session_id == session_id).first()
        if not log_record:
            return None
        
        # 취약점 분석 결과 조회
        vul_records = db.query(LSTM_VUL).filter(LSTM_VUL.session_id == session_id).all()
        
        # 악성 코드 분석 결과 조회
        mal_records = db.query(LSTM_MAL).filter(LSTM_MAL.session_id == session_id).all()
        
        return {
            "session_id": session_id,
            "upload_time": log_record.upload_time,
            "filename": log_record.filename,
            "file_size": log_record.file_size,
            "analysis_model": log_record.analysis_model,
            "analysis_duration": log_record.analysis_duration,
            "total_files": log_record.total_files,
            "safe_files": log_record.safe_files,
            "vulnerable_files": log_record.vulnerable_files,
            "malicious_files": log_record.malicious_files,
            "is_safe": log_record.is_safe,
            "vulnerability_results": [
                {
                    "file_path": record.file_path,
                    "file_name": record.file_name,
                    "vulnerability_status": record.vulnerability_status,
                    "vulnerability_probability": record.vulnerability_probability,
                    "vulnerability_label": record.vulnerability_label,
                    "cwe_label": record.cwe_label,
                    "analysis_time": record.analysis_time
                }
                for record in vul_records
            ],
            "malicious_results": [
                {
                    "file_path": record.file_path,
                    "file_name": record.file_name,
                    "malicious_status": record.malicious_status,
                    "malicious_probability": record.malicious_probability,
                    "malicious_label": record.malicious_label,
                    "analysis_time": record.analysis_time
                }
                for record in mal_records
            ]
        }
        
    except Exception as e:
        print(f"❌ Error getting session summary: {e}")
        return None
    finally:
        db.close()

def get_stats() -> Dict[str, Any]:
    """통계 정보 조회"""
    db = get_db()
    try:
        # main_log에서 전체 통계 조회
        total_sessions = db.query(main_log).count()
        total_files = db.query(main_log).with_entities(main_log.total_files).all()
        total_files_sum = sum(record[0] for record in total_files if record[0])
        
        safe_files = db.query(main_log).with_entities(main_log.safe_files).all()
        safe_files_sum = sum(record[0] for record in safe_files if record[0])
        
        vulnerable_files = db.query(main_log).with_entities(main_log.vulnerable_files).all()
        vulnerable_files_sum = sum(record[0] for record in vulnerable_files if record[0])
        
        malicious_files = db.query(main_log).with_entities(main_log.malicious_files).all()
        malicious_files_sum = sum(record[0] for record in malicious_files if record[0])
        
        return {
            "total_sessions": total_sessions,
            "total_files": total_files_sum,
            "safe_files": safe_files_sum,
            "vulnerable_files": vulnerable_files_sum,
            "malicious_files": malicious_files_sum,
            "malicious_rate": (malicious_files_sum / total_files_sum * 100) if total_files_sum > 0 else 0,
            "vulnerable_rate": (vulnerable_files_sum / total_files_sum * 100) if total_files_sum > 0 else 0,
            "safe_rate": (safe_files_sum / total_files_sum * 100) if total_files_sum > 0 else 0
        }
        
    except Exception as e:
        print(f"❌ Error getting stats: {e}")
        return {
            "total_sessions": 0,
            "total_files": 0,
            "safe_files": 0,
            "vulnerable_files": 0,
            "malicious_files": 0,
            "malicious_rate": 0,
            "vulnerable_rate": 0,
            "safe_rate": 0
        }
    finally:
        db.close()

def get_recent_sessions(limit: int = 10) -> List[Dict[str, Any]]:
    """최근 세션 목록 조회"""
    db = get_db()
    try:
        sessions = db.query(main_log).order_by(main_log.created_at.desc()).limit(limit).all()
        
        return [
            {
                "session_id": session.session_id,
                "upload_time": session.upload_time,
                "filename": session.filename,
                "file_size": session.file_size,
                "analysis_model": session.analysis_model,
                "analysis_duration": session.analysis_duration,
                "total_files": session.total_files,
                "safe_files": session.safe_files,
                "vulnerable_files": session.vulnerable_files,
                "malicious_files": session.malicious_files,
                "is_safe": session.is_safe,
                "created_at": session.created_at
            }
            for session in sessions
        ]
        
    except Exception as e:
        print(f"❌ Error getting recent sessions: {e}")
        return []
    finally:
        db.close()

"""
통합 데이터베이스 모듈 - AI 분석 결과 저장 및 관리
=================================================

이 모듈은 Python 코드의 보안 분석 결과를 저장하고 관리하는 데이터베이스 시스템입니다.

데이터베이스 구조:
- lstm_vul: 취약점 분석 결과 테이블
- lstm_mal: 악성코드 분석 결과 테이블  
- main_log: 분석 세션 요약 로그 테이블

주요 기능:
- 분석 결과 저장 및 조회
- 세션별 데이터 관리
- 통계 정보 제공
- 데이터 무결성 보장

사용 기술:
- SQLAlchemy ORM
- SQLite 데이터베이스
- 비동기 데이터 처리
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

class LSTM_VUL_SAFE(Base):
    """안전한 파일 (취약점 분석 관점) 기록 테이블"""
    __tablename__ = "lstm_vul_safe"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    file_path = Column(String)
    file_name = Column(String)
    file_size = Column(Integer)
    vulnerability_status = Column(String)  # 항상 "Safe"
    vulnerability_probability = Column(Float)
    cwe_label = Column(String)
    analysis_time = Column(Float)
    upload_time = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

class LSTM_MAL_SAFE(Base):
    """안전한 파일 (악성코드 분석 관점) 기록 테이블"""
    __tablename__ = "lstm_mal_safe"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    file_path = Column(String)
    file_name = Column(String)
    file_size = Column(Integer)
    malicious_status = Column(String)  # 항상 "Safe"
    malicious_probability = Column(Float)
    analysis_time = Column(Float)
    upload_time = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

class PKG_VUL_ANALYSIS(Base):
    """패키지 취약점 분석 결과 테이블 (LSTM + XGBoost 통합)"""
    __tablename__ = "pkg_vul_analysis"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    package_name = Column(String, index=True)
    
    # 메타데이터 정보
    summary = Column(Text)
    author = Column(String)
    author_email = Column(String)
    version = Column(String)
    download_count = Column(Integer)
    
    # LSTM 분석 결과
    lstm_vulnerability_status = Column(String)  # "Vulnerable" or "Not Vulnerable"
    lstm_cwe_label = Column(String)
    lstm_confidence = Column(Float)
    
    # XGBoost ML 분석 결과
    xgboost_prediction = Column(Integer)  # 0: 정상, 1: 악성
    xgboost_confidence = Column(Float)
    
    # 통합 분석 결과
    final_malicious_status = Column(Boolean)  # True: 악성, False: 정상
    threat_level = Column(Integer)  # 0: 낮음, 1: 보통, 2: 높음
    
    # 분석 메타데이터
    analysis_time = Column(Float)
    upload_time = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

class BERT_MAL(Base):
    """BERT 악성코드 분석 결과 테이블"""
    __tablename__ = "bert_mal"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    file_path = Column(String)
    file_name = Column(String)
    file_size = Column(Integer)
    malicious_status = Column(String)
    malicious_probability = Column(Float)
    malicious_label = Column(String)
    analysis_time = Column(Float)
    upload_time = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

class BERT_MAL_SAFE(Base):
    """안전한 파일 (BERT 악성코드 분석 관점) 기록 테이블"""
    __tablename__ = "bert_mal_safe"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    file_path = Column(String)
    file_name = Column(String)
    file_size = Column(Integer)
    malicious_status = Column(String)  # 항상 "Safe"
    malicious_probability = Column(Float)
    analysis_time = Column(Float)
    upload_time = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

class BERT_VUL(Base):
    """BERT 취약점 분석 결과 테이블"""
    __tablename__ = "bert_vul"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    file_path = Column(String)
    file_name = Column(String)
    file_size = Column(Integer)
    vulnerability_status = Column(String)
    vulnerability_probability = Column(Float)
    vulnerability_label = Column(String)
    cwe_label = Column(String)
    analysis_time = Column(Float)
    upload_time = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

class BERT_VUL_SAFE(Base):
    """안전한 파일 (BERT 취약점 분석 관점) 기록 테이블"""
    __tablename__ = "bert_vul_safe"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    file_path = Column(String)
    file_name = Column(String)
    file_size = Column(Integer)
    vulnerability_status = Column(String)  # 항상 "Safe"
    vulnerability_probability = Column(Float)
    cwe_label = Column(String)
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
    vul_flag = Column(Boolean, default=False)
    mal_flag = Column(Boolean, default=False)
    is_bert = Column(Boolean, default=False) # BERT 모델 사용 여부
    is_mal = Column(Boolean, default=False) # 악성코드 분석 여부 (LSTM/BERT 구분)
    is_ml = Column(Boolean, default=False) # ML 통합 분석 여부 (LSTM + XGBoost)
    is_safe = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

def init_database():
    """통합 데이터베이스 초기화"""
    try:
        # 모든 테이블 생성
        Base.metadata.create_all(bind=engine)
        
        # 기존 main_log 테이블에 is_ml 컬럼 추가 (없는 경우에만)
        try:
            with engine.connect() as conn:
                # is_ml 컬럼이 있는지 확인
                result = conn.execute("PRAGMA table_info(main_log)")
                columns = [row[1] for row in result.fetchall()]
                
                if 'is_ml' not in columns:
                    print("🔧 Adding is_ml column to main_log table...")
                    conn.execute("ALTER TABLE main_log ADD COLUMN is_ml BOOLEAN DEFAULT 0")
                    conn.commit()
                    print("✅ is_ml column added successfully")
                else:
                    print("✅ is_ml column already exists")
        except Exception as e:
            print(f"⚠️ Error adding is_ml column: {e}")

        # pkg_vul_analysis 테이블에 package_name 컬럼 존재 보장
        try:
            with engine.connect() as conn:
                result = conn.execute("PRAGMA table_info(pkg_vul_analysis)")
                pkg_columns = [row[1] for row in result.fetchall()]
                if 'package_name' not in pkg_columns:
                    print("🔧 Adding package_name column to pkg_vul_analysis table...")
                    conn.execute("ALTER TABLE pkg_vul_analysis ADD COLUMN package_name TEXT")
                    conn.commit()
                    print("✅ package_name column added successfully")
                else:
                    print("✅ package_name column already exists in pkg_vul_analysis")
        except Exception as e:
            print(f"⚠️ Error ensuring package_name column on pkg_vul_analysis: {e}")
        
        print("✅ Integrated database initialized successfully")
        print(f"📁 Database file: {DB_PATH}")
        print("📊 Tables created: lstm_vul, lstm_mal, lstm_vul_safe, lstm_mal_safe, bert_mal, bert_mal_safe, bert_vul, bert_vul_safe, pkg_vul_analysis, main_log")
        print("🔧 BERT integration: server/models/bert_mal (malicious), server/models/bert_vul (vulnerability)")
        print("🧠 ML integration: pkg_vul_analysis table for LSTM + XGBoost results")
    except Exception as e:
        print(f"❌ Error initializing integrated database: {e}")

def get_db() -> Session:
    """데이터베이스 세션 반환"""
    db = SessionLocal()
    try:
        return db
    finally:
        pass

def save_analysis_results(session_id: str, results: List[Dict[str, Any]], upload_info: Dict[str, Any], mode: str = "both", is_bert: bool = False, is_ml: bool = False) -> Dict[str, Any]:
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

            # 모드별 저장 로직 - 실제 문제가 있는 파일만 저장
            if mode in ("both", "vul"):
                # 취약점 분석 결과 저장 (실제 취약한 파일만)
                vul_analysis = result.get("vulnerability_analysis", {})
                is_vulnerable = bool(vul_analysis.get("is_vulnerable", False))
                if is_vulnerable:
                    vulnerability_results += 1
                    
                    if is_bert:
                        # BERT 취약점 테이블에 저장
                        vul_record = BERT_VUL(
                            session_id=session_id,
                            file_path=result.get("file_path", ""),
                            file_name=result.get("file_name", ""),
                            file_size=result.get("file_size", 0),
                            vulnerability_status="Vulnerable",
                            vulnerability_probability=vul_analysis.get("vulnerability_probability", 0.0),
                            vulnerability_label=vul_analysis.get("vulnerability_label", ""),
                            cwe_label=vul_analysis.get("cwe_label", ""),
                            analysis_time=result.get("analysis_time", 0.0),
                            upload_time=upload_info.get("upload_time", datetime.utcnow())
                        )
                    else:
                        # LSTM 취약점 테이블에 저장
                        vul_record = LSTM_VUL(
                            session_id=session_id,
                            file_path=result.get("file_path", ""),
                            file_name=result.get("file_name", ""),
                            file_size=result.get("file_size", 0),
                            vulnerability_status="Vulnerable",
                            vulnerability_probability=vul_analysis.get("vulnerability_probability", 0.0),
                            vulnerability_label=vul_analysis.get("vulnerability_label", ""),
                            cwe_label=vul_analysis.get("cwe_label", ""),
                            analysis_time=result.get("analysis_time", 0.0),
                            upload_time=upload_info.get("upload_time", datetime.utcnow())
                        )
                    db.add(vul_record)
                else:
                    # 안전한 파일은 SAFE 테이블에 기록
                    if is_bert:
                        vul_safe = BERT_VUL_SAFE(
                            session_id=session_id,
                            file_path=result.get("file_path", ""),
                            file_name=result.get("file_name", ""),
                            file_size=result.get("file_size", 0),
                            vulnerability_status="Safe",
                            vulnerability_probability=vul_analysis.get("vulnerability_probability", 0.0),
                            cwe_label=vul_analysis.get("cwe_label", "Safe"),
                            analysis_time=result.get("analysis_time", 0.0),
                            upload_time=upload_info.get("upload_time", datetime.utcnow())
                        )
                    else:
                        vul_safe = LSTM_VUL_SAFE(
                            session_id=session_id,
                            file_path=result.get("file_path", ""),
                            file_name=result.get("file_name", ""),
                            file_size=result.get("file_size", 0),
                            vulnerability_status="Safe",
                            vulnerability_probability=vul_analysis.get("vulnerability_probability", 0.0),
                            cwe_label=vul_analysis.get("cwe_label", "Safe"),
                            analysis_time=result.get("analysis_time", 0.0),
                            upload_time=upload_info.get("upload_time", datetime.utcnow())
                        )
                    db.add(vul_safe)

            if mode in ("both", "mal"):
                # 악성 코드 분석 결과 저장 (실제 악성인 파일만)
                mal_analysis = result.get("malicious_analysis", {})
                is_malicious = bool(mal_analysis.get("is_malicious", False))
                if is_malicious:
                    malicious_results += 1
                    
                    if is_bert:
                        # BERT 악성코드 테이블에 저장
                        mal_record = BERT_MAL(
                            session_id=session_id,
                            file_path=result.get("file_path", ""),
                            file_name=result.get("file_name", ""),
                            file_size=result.get("file_size", 0),
                            malicious_status="malicious",
                            malicious_probability=mal_analysis.get("malicious_probability", 0.0),
                            malicious_label=mal_analysis.get("malicious_label", ""),
                            analysis_time=result.get("analysis_time", 0.0),
                            upload_time=upload_info.get("upload_time", datetime.utcnow())
                        )
                    else:
                        # LSTM 악성코드 테이블에 저장
                        mal_record = LSTM_MAL(
                            session_id=session_id,
                            file_path=result.get("file_path", ""),
                            file_name=result.get("file_name", ""),
                            file_size=result.get("file_size", 0),
                            malicious_status="malicious",
                            malicious_probability=mal_analysis.get("malicious_probability", 0.0),
                            malicious_label=mal_analysis.get("malicious_label", ""),
                            analysis_time=result.get("analysis_time", 0.0),
                            upload_time=upload_info.get("upload_time", datetime.utcnow())
                        )
                    db.add(mal_record)
                else:
                    # 안전한 파일은 SAFE 테이블에 기록
                    if is_bert:
                        mal_safe = BERT_MAL_SAFE(
                            session_id=session_id,
                            file_path=result.get("file_path", ""),
                            file_name=result.get("file_name", ""),
                            file_size=result.get("file_size", 0),
                            malicious_status="Safe",
                            malicious_probability=mal_analysis.get("malicious_probability", 0.0),
                            analysis_time=result.get("analysis_time", 0.0),
                            upload_time=upload_info.get("upload_time", datetime.utcnow())
                        )
                    else:
                        mal_safe = LSTM_MAL_SAFE(
                            session_id=session_id,
                            file_path=result.get("file_path", ""),
                            file_name=result.get("file_name", ""),
                            file_size=result.get("file_size", 0),
                            malicious_status="Safe",
                            malicious_probability=mal_analysis.get("malicious_probability", 0.0),
                            analysis_time=result.get("analysis_time", 0.0),
                            upload_time=upload_info.get("upload_time", datetime.utcnow())
                        )
                    db.add(mal_safe)

            # 안전한 파일 카운트 (분석 모드에 따라 다르게 계산)
            vul_analysis = result.get("vulnerability_analysis", {})
            mal_analysis = result.get("malicious_analysis", {})
            is_vulnerable = bool(vul_analysis.get("is_vulnerable", False))
            is_malicious = bool(mal_analysis.get("is_malicious", False))
            
            # 분석 모드에 따른 안전한 파일 카운트
            if mode == "mal":  # 악성코드만 분석
                if not is_malicious:
                    safe_files += 1
            elif mode == "vul":  # 취약점만 분석
                if not is_vulnerable:
                    safe_files += 1
            else:  # both 모드
                if not is_vulnerable and not is_malicious:
                    safe_files += 1
        
        # main_log에 요약 저장
        total_files = len(results)
        is_safe = (vulnerability_results == 0 and malicious_results == 0)
        
        # 세션 플래그: 분석 모드 및 실제 결과 기반
        vul_flag_value = (mode in ("both", "vul")) and (vulnerability_results > 0)
        mal_flag_value = (mode in ("both", "mal")) and (malicious_results > 0)
        
        # 모델 타입에 따른 분석 모델명 설정
        if is_bert:
            analysis_model_name = "Integrated BERT"
        else:
            analysis_model_name = "Integrated LSTM"

        log_record = main_log(
            session_id=session_id,
            upload_time=upload_info.get("upload_time", datetime.utcnow()),
            filename=upload_info.get("filename", ""),
            file_size=upload_info.get("file_size", 0),
            analysis_model=analysis_model_name,
            analysis_duration=total_analysis_time,
            total_files=total_files,
            safe_files=safe_files,
            vulnerable_files=vulnerability_results,
            malicious_files=malicious_results,
            vul_flag=vul_flag_value,
            mal_flag=mal_flag_value,
            is_bert=is_bert,
            is_mal=(mode == "mal"),  # 악성코드만 분석하는 경우
            is_ml=is_ml,  # ML 분석 여부
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
        
        # 분석 타입 확인
        is_bert_analysis = bool(log_record.is_bert) if log_record.is_bert is not None else False
        is_ml_analysis = bool(log_record.is_ml) if log_record.is_ml is not None else False
        
        # 변수 초기화
        vul_records = []
        vul_safe_records = []
        mal_records = []
        mal_safe_records = []
        ml_records = []
        unique_safe_files = 0
        
        if is_ml_analysis:
            # ML 분석 결과 조회
            ml_records = db.query(PKG_VUL_ANALYSIS).filter(PKG_VUL_ANALYSIS.session_id == session_id).all()
            unique_safe_files = sum(1 for r in ml_records if not r.final_malicious_status and r.lstm_vulnerability_status != "Vulnerable")
        elif is_bert_analysis:
            # BERT 분석 결과 조회
            vul_records = db.query(BERT_VUL).filter(BERT_VUL.session_id == session_id).all()
            vul_safe_records = db.query(BERT_VUL_SAFE).filter(BERT_VUL_SAFE.session_id == session_id).all()
            
            # BERT 악성 코드 분석 결과 조회
            mal_records = db.query(BERT_MAL).filter(BERT_MAL.session_id == session_id).all()
            mal_safe_records = db.query(BERT_MAL_SAFE).filter(BERT_MAL_SAFE.session_id == session_id).all()
        else:
            # LSTM 분석 결과 조회
            vul_records = db.query(LSTM_VUL).filter(LSTM_VUL.session_id == session_id).all()
            vul_safe_records = db.query(LSTM_VUL_SAFE).filter(LSTM_VUL_SAFE.session_id == session_id).all()
            
            # LSTM 악성 코드 분석 결과 조회
            mal_records = db.query(LSTM_MAL).filter(LSTM_MAL.session_id == session_id).all()
            mal_safe_records = db.query(LSTM_MAL_SAFE).filter(LSTM_MAL_SAFE.session_id == session_id).all()
        
        # 분석 모드에 따른 안전한 파일 개수 계산
        if is_bert_analysis:
            # BERT 분석에서는 분석 모드에 따라 개별 계산
            if log_record.is_mal:  # 악성코드만 분석한 경우
                unique_safe_files = len(mal_safe_records)
            else:  # 취약점만 분석하거나 둘 다 분석한 경우
                unique_safe_files = len(vul_safe_records)
        else:
            # LSTM 분석에서는 분석 모드에 따라 개별 계산
            if log_record.is_mal:  # 악성코드만 분석한 경우
                unique_safe_files = len(mal_safe_records)
            else:  # 취약점만 분석하거나 둘 다 분석한 경우
                unique_safe_files = len(vul_safe_records)

        return {
            "session_id": session_id,
            "upload_time": log_record.upload_time.isoformat() if log_record.upload_time else None,
            "filename": log_record.filename,
            "file_size": int(log_record.file_size) if log_record.file_size else 0,
            "analysis_model": log_record.analysis_model,
            "analysis_duration": float(log_record.analysis_duration) if log_record.analysis_duration else 0.0,
            "total_files": int(log_record.total_files) if log_record.total_files else 0,
            "safe_files": unique_safe_files,  # 분석 모드에 따른 안전한 파일 개수
            "vulnerable_files": int(log_record.vulnerable_files) if log_record.vulnerable_files else 0,
            "malicious_files": int(log_record.malicious_files) if log_record.malicious_files else 0,
            "vul_flag": bool(log_record.vul_flag) if log_record.vul_flag is not None else False,
            "mal_flag": bool(log_record.mal_flag) if log_record.mal_flag is not None else False,
            "is_bert": bool(log_record.is_bert) if log_record.is_bert is not None else False,
            "is_mal": bool(log_record.is_mal) if log_record.is_mal is not None else False,
            "is_ml": bool(log_record.is_ml) if log_record.is_ml is not None else False,
            "is_safe": bool(log_record.is_safe) if log_record.is_safe is not None else True,
            "vulnerability_results": [
                {
                    "file_path": str(record.file_path) if record.file_path else "",
                    "file_name": str(record.file_name) if record.file_name else "",
                    "vulnerability_status": str(record.vulnerability_status) if record.vulnerability_status else "",
                    "vulnerability_probability": float(record.vulnerability_probability) if record.vulnerability_probability else 0.0,
                    "vulnerability_label": str(record.vulnerability_label) if record.vulnerability_label else "",
                    "cwe_label": str(record.cwe_label) if record.cwe_label else "",
                    "analysis_time": float(record.analysis_time) if record.analysis_time else 0.0
                }
                for record in vul_records
            ],
            "vulnerability_safe_results": [
                {
                    "file_path": str(record.file_path) if record.file_path else "",
                    "file_name": str(record.file_name) if record.file_name else "",
                    "vulnerability_status": str(record.vulnerability_status) if record.vulnerability_status else "Safe",
                    "vulnerability_probability": float(record.vulnerability_probability) if record.vulnerability_probability else 0.0,
                    "cwe_label": str(record.cwe_label) if record.cwe_label else "Safe",
                    "analysis_time": float(record.analysis_time) if record.analysis_time else 0.0
                }
                for record in vul_safe_records
            ],
            "malicious_results": [
                {
                    "file_path": str(record.file_path) if record.file_path else "",
                    "file_name": str(record.file_name) if record.file_name else "",
                    "malicious_status": str(record.malicious_status) if record.malicious_status else "",
                    "malicious_probability": float(record.malicious_probability) if record.malicious_probability else 0.0,
                    "malicious_label": str(record.malicious_label) if record.malicious_label else "",
                    "analysis_time": float(record.analysis_time) if record.analysis_time else 0.0
                }
                for record in mal_records
            ],
            "malicious_safe_results": [
                {
                    "file_path": str(record.file_path) if record.file_path else "",
                    "file_name": str(record.file_name) if record.file_name else "",
                    "malicious_status": str(record.malicious_status) if record.malicious_status else "Safe",
                    "malicious_probability": float(record.malicious_probability) if record.malicious_probability else 0.0,
                    "analysis_time": float(record.analysis_time) if record.analysis_time else 0.0
                }
                for record in mal_safe_records
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
                "vul_flag": session.vul_flag,
                "mal_flag": session.mal_flag,
                "is_bert": session.is_bert,
                "is_mal": session.is_mal,
                "is_ml": session.is_ml,
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

# =============================================================================
# PKG_VUL_ANALYSIS 관련 CRUD 함수들
# =============================================================================

def save_pkg_vul_analysis_results(session_id: str, results: List[Dict[str, Any]]) -> bool:
    """패키지 취약점 분석 결과 저장"""
    db = get_db()
    try:
        for result in results:
            pkg_analysis = PKG_VUL_ANALYSIS(
                session_id=session_id,
                package_name=result.get("package_name", ""),
                summary=result.get("summary", ""),
                author=result.get("author", ""),
                author_email=result.get("author_email", ""),
                version=result.get("version", ""),
                download_count=result.get("download_count", 0),
                lstm_vulnerability_status=result.get("lstm_vulnerability_status", ""),
                lstm_cwe_label=result.get("lstm_cwe_label", ""),
                lstm_confidence=result.get("lstm_confidence", 0.0),
                xgboost_prediction=result.get("xgboost_prediction", 0),
                xgboost_confidence=result.get("xgboost_confidence", 0.0),
                final_malicious_status=result.get("final_malicious_status", False),
                threat_level=result.get("threat_level", 0),
                analysis_time=result.get("analysis_time", 0.0)
            )
            db.add(pkg_analysis)
        
        db.commit()
        print(f"✅ Saved {len(results)} package analysis results for session {session_id}")
        return True
        
    except Exception as e:
        print(f"❌ Error saving package analysis results: {e}")
        db.rollback()
        return False
    finally:
        db.close()

def save_ml_analysis_log(session_id: str, upload_info: Dict[str, Any], results: List[Dict[str, Any]], analysis_time: float) -> bool:
    """ML 분석 결과를 main_log에 저장"""
    db = get_db()
    try:
        # 통계 계산
        total_packages = len(results)
        malicious_packages = sum(1 for r in results if r.get("final_malicious_status", False))
        vulnerable_packages = sum(1 for r in results if r.get("lstm_vulnerability_status") == "Vulnerable")
        safe_packages = total_packages - malicious_packages - vulnerable_packages
        
        # main_log에 저장
        log_record = main_log(
            session_id=session_id,
            upload_time=upload_info.get("upload_time", datetime.utcnow()),
            filename=upload_info.get("filename", ""),
            file_size=upload_info.get("file_size", 0),
            analysis_model="ML (LSTM + XGBoost)",
            analysis_duration=analysis_time,
            total_files=total_packages,
            safe_files=safe_packages,
            vulnerable_files=vulnerable_packages,
            malicious_files=malicious_packages,
            vul_flag=vulnerable_packages > 0,
            mal_flag=malicious_packages > 0,
            is_bert=False,
            is_mal=False,
            is_ml=True,  # ML 분석 플래그
            is_safe=safe_packages == total_packages
        )
        
        db.add(log_record)
        db.commit()
        print(f"✅ Saved ML analysis log for session {session_id}")
        return True
    except Exception as e:
        print(f"❌ Error saving ML analysis log: {e}")
        db.rollback()
        return False
    finally:
        db.close()

def get_pkg_vul_analysis_by_session(session_id: str) -> List[Dict[str, Any]]:
    """세션별 패키지 취약점 분석 결과 조회"""
    db = get_db()
    try:
        results = db.query(PKG_VUL_ANALYSIS).filter(
            PKG_VUL_ANALYSIS.session_id == session_id
        ).all()
        
        analysis_results = []
        for result in results:
            analysis_results.append({
                "id": result.id,
                "session_id": result.session_id,
                "package_name": result.package_name,
                "summary": result.summary,
                "author": result.author,
                "author_email": result.author_email,
                "version": result.version,
                "download_count": result.download_count,
                "lstm_vulnerability_status": result.lstm_vulnerability_status,
                "lstm_cwe_label": result.lstm_cwe_label,
                "lstm_confidence": result.lstm_confidence,
                "xgboost_prediction": result.xgboost_prediction,
                "xgboost_confidence": result.xgboost_confidence,
                "final_malicious_status": result.final_malicious_status,
                "threat_level": result.threat_level,
                "analysis_time": result.analysis_time,
                "upload_time": result.upload_time.isoformat() if result.upload_time else None,
                "created_at": result.created_at.isoformat() if result.created_at else None
            })
        
        return analysis_results
        
    except Exception as e:
        print(f"❌ Error getting package analysis results: {e}")
        return []
    finally:
        db.close()

def get_pkg_vul_analysis_summary(session_id: str) -> Dict[str, Any]:
    """패키지 취약점 분석 결과 요약"""
    db = get_db()
    try:
        results = db.query(PKG_VUL_ANALYSIS).filter(
            PKG_VUL_ANALYSIS.session_id == session_id
        ).all()
        
        total_packages = len(results)
        malicious_packages = sum(1 for r in results if r.final_malicious_status)
        vulnerable_packages = sum(1 for r in results if r.lstm_vulnerability_status == "Vulnerable")
        safe_packages = sum(1 for r in results if not r.final_malicious_status and r.lstm_vulnerability_status != "Vulnerable")
        
        return {
            "session_id": session_id,
            "total_packages": total_packages,
            "malicious_packages": malicious_packages,
            "vulnerable_packages": vulnerable_packages,
            "safe_packages": safe_packages,
            "malicious_rate": (malicious_packages / total_packages * 100) if total_packages > 0 else 0,
            "vulnerable_rate": (vulnerable_packages / total_packages * 100) if total_packages > 0 else 0,
            "safe_rate": (safe_packages / total_packages * 100) if total_packages > 0 else 0
        }
        
    except Exception as e:
        print(f"❌ Error getting package analysis summary: {e}")
        return {
            "session_id": session_id,
            "total_packages": 0,
            "malicious_packages": 0,
            "vulnerable_packages": 0,
            "safe_packages": 0,
            "malicious_rate": 0,
            "vulnerable_rate": 0,
            "safe_rate": 0
        }
    finally:
        db.close()

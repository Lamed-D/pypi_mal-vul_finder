"""
SQLite database configuration and models
"""
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os

from config import DATABASE_URL

# Create database engine
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class AnalysisSession(Base):
    """분석 세션 정보"""
    __tablename__ = "analysis_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(50), unique=True, index=True)
    filename = Column(String(255), nullable=False)
    file_size = Column(Integer)
    upload_time = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default="pending")  # pending, processing, completed, failed
    total_files = Column(Integer, default=0)
    processed_files = Column(Integer, default=0)
    error_message = Column(Text)
    
    # Relationships
    files = relationship("AnalyzedFile", back_populates="session")

class AnalyzedFile(Base):
    """분석된 파일 정보"""
    __tablename__ = "analyzed_files"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(50), ForeignKey("analysis_sessions.session_id"))
    file_path = Column(String(500), nullable=False)
    file_name = Column(String(255), nullable=False)
    file_size = Column(Integer)
    
    # Analysis results
    is_malicious = Column(Boolean, default=False)
    is_vulnerable = Column(Boolean, default=False)
    malicious_probability = Column(Float, default=0.0)
    vulnerability_probability = Column(Float, default=0.0)
    
    # CodeBERT results
    cwe_label = Column(String(100))
    cwe_probability = Column(Float)
    cwe_topk = Column(Text)  # JSON string
    
    # LSTM results
    lstm_label = Column(String(100))
    lstm_probability = Column(Float)
    
    # Metadata analysis results
    metadata_analysis = Column(Text)  # JSON string
    is_typo_like = Column(Boolean, default=False)
    download_count = Column(Integer)
    download_log = Column(Float)
    summary_length = Column(Integer)
    summary_entropy = Column(Float)
    summary_low_entropy = Column(Boolean)
    version_valid = Column(Boolean)
    package_name = Column(String(255))
    version = Column(String(50))
    author = Column(String(255))
    author_email = Column(String(255))
    
    # Analysis metadata
    analysis_time = Column(Float)  # seconds
    analysis_method = Column(String(50))  # codebert, lstm, metadata, unified
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    session = relationship("AnalysisSession", back_populates="files")

class AnalysisLog(Base):
    """분석 로그"""
    __tablename__ = "analysis_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(50), ForeignKey("analysis_sessions.session_id"))
    level = Column(String(20), default="INFO")  # INFO, WARNING, ERROR
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    file_path = Column(String(500))

def create_tables():
    """Create all tables"""
    Base.metadata.create_all(bind=engine)

def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_database():
    """Initialize database with tables"""
    create_tables()
    print("Database initialized successfully")

if __name__ == "__main__":
    init_database()

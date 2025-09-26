"""
Analysis service for coordinating different analysis engines
"""
from typing import Dict, Any, List
import asyncio
from datetime import datetime

from analysis.unified_analyzer import UnifiedAnalyzer
from database.database import AnalysisSession, AnalyzedFile, AnalysisLog, get_db

class AnalysisService:
    def __init__(self):
        try:
            self.analyzer = UnifiedAnalyzer()
            print("UnifiedAnalyzer initialized successfully")
        except Exception as e:
            print(f"Error initializing UnifiedAnalyzer: {e}")
            self.analyzer = None
    
    async def analyze_session(self, session_id: str, file_path: str) -> Dict[str, Any]:
        """Analyze all files in a session and save to database"""
        db = next(get_db())
        try:
            print(f"Starting analysis for session {session_id}, file: {file_path}")
            
            if not self.analyzer:
                raise Exception("UnifiedAnalyzer not initialized")
            
            # Extract files from ZIP
            files = self.analyzer.extract_zip_file(file_path)
            
            if not files:
                # Update session status
                session = db.query(AnalysisSession).filter(AnalysisSession.id == session_id).first()
                if session:
                    session.status = "failed"
                    session.error_message = "No files found in ZIP"
                    db.commit()
                return {
                    "success": False,
                    "message": "No files found in ZIP",
                    "processed_files": 0,
                    "total_files": 0
                }
            
            # Update session with total files count
            session = db.query(AnalysisSession).filter(AnalysisSession.id == session_id).first()
            if session:
                session.total_files = len(files)
                db.commit()
            
            # Analyze each file
            results = []
            processed_count = 0
            
            for file_info in files:
                try:
                    result = await self.analyzer.analyze_file(
                        file_info["path"], 
                        file_info["content"]
                    )
                    results.append(result)
                    processed_count += 1
                    
                    # Save analyzed file to database
                    analyzed_file = AnalyzedFile(
                        session_id=session_id,
                        filename=file_info["path"],
                        file_content=file_info["content"][:1000],  # Limit content length
                        is_malicious=result.get("is_malicious", False),
                        is_vulnerable=result.get("is_vulnerable", False),
                        malicious_probability=result.get("malicious_probability", 0.0),
                        vulnerability_probability=result.get("vulnerability_probability", 0.0),
                        cwe_label=result.get("cwe_label"),
                        cwe_probability=result.get("cwe_probability"),
                        lstm_label=result.get("lstm_label"),
                        lstm_probability=result.get("lstm_probability"),
                        metadata_analysis=result.get("metadata_analysis"),
                        is_typo_like=result.get("is_typo_like", False),
                        download_log=result.get("download_log"),
                        summary_length=result.get("summary_length"),
                        summary_entropy=result.get("summary_entropy"),
                        summary_low_entropy=result.get("summary_low_entropy"),
                        version_valid=result.get("version_valid"),
                        package_name=result.get("package_name"),
                        version=result.get("version"),
                        author=result.get("author"),
                        author_email=result.get("author_email"),
                        analysis_time=result.get("analysis_time", 0.0),
                        analysis_method=result.get("analysis_method", "unified")
                    )
                    
                    db.add(analyzed_file)
                    db.commit()
                    
                except Exception as e:
                    print(f"Error analyzing file {file_info['path']}: {e}")
                    continue
            
            # Update session status to completed
            session = db.query(AnalysisSession).filter(AnalysisSession.id == session_id).first()
            if session:
                session.status = "completed"
                session.processed_files = processed_count
                db.commit()
            
            return {
                "success": True,
                "message": f"Analyzed {processed_count} files",
                "processed_files": processed_count,
                "total_files": len(files),
                "results": results
            }
            
        except Exception as e:
            # Update session status to failed
            session = db.query(AnalysisSession).filter(AnalysisSession.id == session_id).first()
            if session:
                session.status = "failed"
                session.error_message = str(e)
                db.commit()
            
            return {
                "success": False,
                "message": f"Analysis failed: {str(e)}",
                "processed_files": 0,
                "total_files": 0,
                "error": str(e)
            }
        finally:
            db.close()
    
    async def analyze_single_file(self, file_path: str, file_content: str) -> Dict[str, Any]:
        """Analyze a single file"""
        return await self.analyzer.analyze_file(file_path, file_content)
    
    def get_analysis_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get summary statistics from analysis results"""
        if not results:
            return {
                "total_files": 0,
                "malicious_files": 0,
                "vulnerable_files": 0,
                "malicious_rate": 0.0,
                "vulnerable_rate": 0.0
            }
        
        total_files = len(results)
        malicious_files = sum(1 for r in results if r.get("is_malicious", False))
        vulnerable_files = sum(1 for r in results if r.get("is_vulnerable", False))
        
        return {
            "total_files": total_files,
            "malicious_files": malicious_files,
            "vulnerable_files": vulnerable_files,
            "malicious_rate": (malicious_files / total_files * 100) if total_files > 0 else 0.0,
            "vulnerable_rate": (vulnerable_files / total_files * 100) if total_files > 0 else 0.0
        }
    
    def log_analysis_event(self, session_id: str, level: str, message: str, file_path: str = None):
        """Log analysis event to database"""
        # This would typically use a database session
        # For now, just print to console
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"[{timestamp}] [{level}] {message}"
        if file_path:
            log_entry += f" (File: {file_path})"
        print(log_entry)

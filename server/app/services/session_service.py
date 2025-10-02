"""세션/통계 관련 데이터 액세스 서비스."""

from typing import List, Dict, Any

from database.database import (
    get_recent_sessions,
    get_stats,
    get_session_summary,
    get_pkg_vul_analysis_by_session,
    get_pkg_vul_analysis_summary,
)


class SessionService:
    """대시보드와 세션 뷰에서 사용하는 데이터 접근 계층."""

    def fetch_recent_sessions(self, limit: int = 10) -> List[Dict[str, Any]]:
        return get_recent_sessions(limit)

    def fetch_stats(self) -> Dict[str, Any]:
        return get_stats()

    def fetch_session_detail(self, session_id: str) -> Dict[str, Any] | None:
        return get_session_summary(session_id)

    def fetch_ml_analysis(self, session_id: str) -> Dict[str, Any]:
        return get_pkg_vul_analysis_by_session(session_id)

    def fetch_ml_summary(self, session_id: str) -> Dict[str, Any]:
        return get_pkg_vul_analysis_summary(session_id)

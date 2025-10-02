from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from fastapi.templating import Jinja2Templates
import json

from app.core.config import settings
from database.database import init_database
from analysis.integrated_lstm_analyzer import IntegratedLSTMAnalyzer
from analysis.bert_analyzer import BERTAnalyzer
from analysis.ml_package_analyzer import MLPackageAnalyzer
from app.services.file_service import FileService
from app.services.event_service import EventManager
from app.services.session_service import SessionService
from app.services.analysis.orchestrator import AnalysisOrchestrator
from app.services.analysis.engines import LazyAnalyzer


@dataclass
class AnalysisEngines:
    lstm: LazyAnalyzer[IntegratedLSTMAnalyzer]
    bert: LazyAnalyzer[BERTAnalyzer]
    ml: LazyAnalyzer[MLPackageAnalyzer]


class AppContainer:
    """애플리케이션 전역에서 공유되는 서비스 및 엔진을 관리한다."""

    def __init__(self, models_dir: Optional[str] = None) -> None:
        # 데이터베이스 초기화는 애플리케이션 시작 시 한 번 수행한다.
        init_database()

        # 핵심 서비스 인스턴스
        self.event_manager = EventManager()
        self.file_service = FileService()
        self.session_service = SessionService()

        # 분석 엔진 초기화 (경로 지정 필요 시 주입 가능)
        self.engines = AnalysisEngines(
            lstm=LazyAnalyzer(lambda: IntegratedLSTMAnalyzer(models_dir)),
            bert=LazyAnalyzer(lambda: BERTAnalyzer(models_dir)),
            ml=LazyAnalyzer(lambda: MLPackageAnalyzer(models_dir)),
        )

        # 분석 파이프라인 오케스트레이션
        self.analysis_orchestrator = AnalysisOrchestrator(
            file_service=self.file_service,
            event_manager=self.event_manager,
            lstm_analyzer=self.engines.lstm,
            bert_analyzer=self.engines.bert,
            ml_analyzer=self.engines.ml,
        )

        # 템플릿 환경
        templates_dir = Path(__file__).parents[1] / "templates"
        self.templates = Jinja2Templates(directory=str(templates_dir))
        self.templates.env.filters["tojson"] = json.dumps

    @property
    def metadata(self) -> dict:
        """FastAPI 메타데이터 생성을 위해 서비스 정보 반환."""
        return {
            "title": f"{settings.service_name} - Python Security Analysis",
            "description": (
                "AI-powered Python code security analysis with vulnerability and "
                "malware detection using LSTM, BERT, and ML models"
            ),
            "version": settings.service_version,
        }

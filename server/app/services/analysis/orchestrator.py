"""분석 파이프라인을 담당하는 오케스트레이터."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Optional

from fastapi import Request
from fastapi.responses import StreamingResponse

from database.database import (
    save_analysis_results,
    save_pkg_vul_analysis_results,
    save_ml_analysis_log,
)
from app.core.config import settings
from app.services.event_service import EventManager
from app.services.file_service import FileService
from analysis.integrated_lstm_analyzer import IntegratedLSTMAnalyzer
from analysis.bert_analyzer import BERTAnalyzer
from analysis.ml_package_analyzer import MLPackageAnalyzer
from app.services.analysis.engines import LazyAnalyzer


class AnalysisOrchestrator:
    """LSTM/BERT/ML 분석 파이프라인을 중앙에서 조정한다."""

    def __init__(
        self,
        file_service: FileService,
        event_manager: EventManager,
        lstm_analyzer: LazyAnalyzer[IntegratedLSTMAnalyzer],
        bert_analyzer: LazyAnalyzer[BERTAnalyzer],
        ml_analyzer: LazyAnalyzer[MLPackageAnalyzer],
    ) -> None:
        self.file_service = file_service
        self.event_manager = event_manager
        self.lstm_analyzer = lstm_analyzer
        self.bert_analyzer = bert_analyzer
        self.ml_analyzer = ml_analyzer

    # ------------------------------------------------------------------
    # SSE 헬퍼
    # ------------------------------------------------------------------
    async def publish_started(
        self,
        session_id: str,
        filename: str,
        model: str,
        mode: Optional[str] = None,
    ) -> None:
        data = {
            "session_id": session_id,
            "filename": filename,
            "status": "processing",
            "model": model,
        }
        if mode:
            data["mode"] = mode
        await self.event_manager.publish(session_id, "analysis_started", data)

    @staticmethod
    def format_sse(payload: dict) -> str:
        event_name = payload.get("event", "message")
        data = payload.get("data", {})
        return f"event: {event_name}\n" f"data: {json.dumps(data)}\n\n"

    async def stream_events(self, session_id: str, request: Request) -> StreamingResponse:
        queue = await self.event_manager.subscribe(session_id)

        async def event_generator():
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    except asyncio.TimeoutError:
                        yield ": keep-alive\n\n"
                        continue

                    yield self.format_sse(event)
            finally:
                await self.event_manager.unsubscribe(session_id, queue)

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    # ------------------------------------------------------------------
    # 분석 파이프라인
    # ------------------------------------------------------------------
    async def analyze_lstm(
        self,
        session_id: str,
        file_path: str,
        filename: str,
        file_size: int,
        mode: str = "both",
    ) -> None:
        try:
            extracted_files = await self.file_service.extract_zip_file(file_path)
            if not extracted_files:
                await self._publish_no_files(session_id, filename, "lstm", mode)
                return

            lstm = self.lstm_analyzer.get()
            analysis_result = await lstm.analyze_files_multiprocess(
                session_id, extracted_files, mode
            )

            if analysis_result["status"] == "completed":
                upload_info = {
                    "upload_time": datetime.now(),
                    "filename": filename,
                    "file_size": file_size,
                }
                save_result = save_analysis_results(
                    session_id,
                    analysis_result["results"],
                    upload_info,
                    mode,
                    is_bert=False,
                )
                await self._publish_success(
                    session_id,
                    filename,
                    "lstm",
                    mode,
                    save_result,
                )
            else:
                await self._publish_failure(
                    session_id,
                    filename,
                    "lstm",
                    mode,
                    analysis_result.get("error", "Unknown error"),
                )
        except Exception as exc:  # pragma: no cover - 예외 로그 유지
            await self._publish_failure(session_id, filename, "lstm", mode, str(exc))

    async def analyze_bert(
        self,
        session_id: str,
        file_path: str,
        filename: str,
        file_size: int,
        mode: str = "both",
    ) -> None:
        try:
            extracted_files = await self.file_service.extract_zip_file(file_path)
            if not extracted_files:
                await self._publish_no_files(session_id, filename, "bert", mode)
                return

            bert = self.bert_analyzer.get()
            analysis_result = await bert.analyze_files_multiprocess(
                session_id, extracted_files, mode
            )

            if analysis_result["status"] == "completed":
                upload_info = {
                    "upload_time": datetime.now(),
                    "filename": filename,
                    "file_size": file_size,
                }
                save_result = save_analysis_results(
                    session_id,
                    analysis_result["results"],
                    upload_info,
                    mode,
                    is_bert=True,
                )
                await self._publish_success(
                    session_id,
                    filename,
                    "bert",
                    mode,
                    save_result,
                )
            else:
                await self._publish_failure(
                    session_id,
                    filename,
                    "bert",
                    mode,
                    analysis_result.get("error", "Unknown error"),
                )
        except Exception as exc:  # pragma: no cover
            await self._publish_failure(session_id, filename, "bert", mode, str(exc))

    async def analyze_ml(
        self,
        session_id: str,
        file_path: str,
        filename: str,
        file_size: int,
    ) -> None:
        try:
            extracted_files = await self.file_service.extract_zip_file(file_path)
            if not extracted_files:
                await self._publish_failure(
                    session_id,
                    filename,
                    "ml",
                    None,
                    "No Python files found in archive",
                )
                return

            extract_dir = settings.upload_dir / session_id / "extracted"
            ml = self.ml_analyzer.get()
            analysis_result = await asyncio.to_thread(
                ml.analyze_extracted_files,
                str(extract_dir),
                extracted_files,
            )

            if "error" in analysis_result:
                await self._publish_failure(
                    session_id,
                    filename,
                    "ml",
                    None,
                    analysis_result["error"],
                )
                return

            if analysis_result.get("success") and analysis_result.get("results"):
                db_results = []
                for result in analysis_result["results"]:
                    db_results.append(
                        {
                            "package_name": result.get("name", ""),
                            "summary": result.get("summary", ""),
                            "author": result.get("author", ""),
                            "author_email": result.get("author-email", ""),
                            "version": result.get("version", ""),
                            "download_count": result.get("download", 0),
                            "lstm_vulnerability_status": result.get(
                                "lstm_vulnerability_status", ""
                            ),
                            "lstm_cwe_label": result.get("lstm_cwe_label", ""),
                            "lstm_confidence": result.get("lstm_confidence", 0.0),
                            "xgboost_prediction": result.get("xgboost_prediction", 0),
                            "xgboost_confidence": result.get("xgboost_confidence", 0.0),
                            "final_malicious_status": bool(
                                result.get("xgboost_prediction", 0)
                            ),
                            "threat_level": 2
                            if result.get("xgboost_prediction", 0) == 1
                            else 0,
                            "analysis_time": analysis_result.get("analysis_time", 0.0),
                        }
                    )

                save_pkg_vul_analysis_results(session_id, db_results)
                upload_info = {
                    "upload_time": datetime.utcnow(),
                    "filename": filename,
                    "file_size": file_size,
                }
                save_ml_analysis_log(
                    session_id,
                    upload_info,
                    analysis_result.get("summary", {}),
                    analysis_result.get("analysis_time", 0.0),
                )

                await self.event_manager.publish(
                    session_id,
                    "analysis_complete",
                    {
                        "session_id": session_id,
                        "model": "ml",
                        "filename": filename,
                        "status": "completed",
                        "summary": analysis_result.get("summary", {}),
                        "redirect_url": f"/session/{session_id}/ML",
                    },
                )
            else:
                await self._publish_failure(
                    session_id,
                    filename,
                    "ml",
                    None,
                    "Analysis returned no results",
                )
        except Exception as exc:  # pragma: no cover
            await self._publish_failure(session_id, filename, "ml", None, str(exc))

    # ------------------------------------------------------------------
    # 내부 유틸리티
    # ------------------------------------------------------------------
    async def _publish_no_files(
        self,
        session_id: str,
        filename: str,
        model: str,
        mode: Optional[str],
    ) -> None:
        upload_info = {
            "upload_time": datetime.now(),
            "filename": filename,
            "file_size": 0,
        }
        save_result = save_analysis_results(
            session_id,
            [],
            upload_info,
            mode or "both",
            is_bert=(model == "bert"),
        )
        await self._publish_success(
            session_id,
            filename,
            model,
            mode,
            save_result,
        )

    async def _publish_success(
        self,
        session_id: str,
        filename: str,
        model: str,
        mode: Optional[str],
        summary: dict,
    ) -> None:
        payload = {
            "session_id": session_id,
            "model": model,
            "filename": filename,
            "status": "completed",
            "summary": {
                "total_files": summary.get("total_files", 0),
                "safe_files": summary.get("safe_files", 0),
                "vulnerable_files": summary.get("vulnerability_results", 0),
                "malicious_files": summary.get("malicious_results", 0),
                "analysis_time": summary.get("total_analysis_time", 0.0),
            },
            "redirect_url": f"/session/{session_id}",
        }
        if mode:
            payload["mode"] = mode
        await self.event_manager.publish(session_id, "analysis_complete", payload)

    async def _publish_failure(
        self,
        session_id: str,
        filename: str,
        model: str,
        mode: Optional[str],
        error: str,
    ) -> None:
        payload = {
            "session_id": session_id,
            "model": model,
            "filename": filename,
            "status": "failed",
            "error": error,
        }
        if mode:
            payload["mode"] = mode
        await self.event_manager.publish(session_id, "analysis_failed", payload)

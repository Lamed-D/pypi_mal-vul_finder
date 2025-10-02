"""
통합 LSTM 분석기 - AI 기반 Python 코드 보안 분석
=================================================

이 모듈은 LSTM 딥러닝 모델을 사용하여 Python 코드의 취약점과 악성코드를 탐지하는 분석 엔진입니다.

주요 기능:
- 취약점 패턴 탐지 (LSTM 모델)
- 악성코드 패턴 탐지 (LSTM 모델)
- 다중 프로세스 병렬 분석
- Word2Vec 기반 코드 토큰 임베딩

분석 프로세스:
1. Python 코드 토큰화 및 전처리
2. Word2Vec 모델로 토큰 임베딩
3. LSTM 모델로 취약점/악성코드 분류
4. 결과 후처리 및 확률 계산

성능 최적화:
- 3개 워커 프로세스로 병렬 처리
- 메모리 효율적인 배치 처리
- 모델 캐싱 및 재사용
"""
import asyncio
import pickle
import os
import numpy as np
import pandas as pd
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Dict, Any, List, Tuple
from pathlib import Path
import re
from gensim.models import Word2Vec

# 프로세스 풀 크기 제한
MAX_WORKERS = 3

class IntegratedLSTMAnalyzer:
    """통합 LSTM 분석기 - 취약점 + 악성 코드 분석"""
    
    def __init__(self, models_dir: str = None):
        self.models_dir = Path(models_dir) if models_dir else Path(__file__).parents[1] / "models"
        self.lstm_dir = self.models_dir / "lstm"
        self.w2v_dir = self.models_dir / "w2v"
        
        # 공통 모델들
        self.w2v_model = None
        self.max_sequence_length = 100
        
        # 취약점 분석 모델들 (safepy_3)
        self.vul_model_final = None  # 이진 분류 모델
        self.vul_model_full = None   # 다중 분류 모델
        self.vul_label_encoder_final = None
        self.vul_label_encoder_full = None
        
        # 악성 코드 분석 모델들 (safepy_3_malicious)
        self.mal_model = None
        self.mal_label_encoder = None
        
        # 프로세스 풀
        self.executor = None
        self.active_tasks = {}
        
        # 모델 로드
        self._load_models()
    
    def _load_models(self):
        """모든 모델 로드"""
        try:
            # Word2Vec 모델 로드 (공통)
            w2v_path = self.w2v_dir / "word2vec_withString10-6-100.model"
            if w2v_path.exists():
                self.w2v_model = Word2Vec.load(str(w2v_path))
                print("✅ Word2Vec model loaded successfully")
            else:
                print(f"❌ Word2Vec model not found: {w2v_path}")
            
            # 취약점 분석 모델 로드 (평면 구조)
            vul_model_path = self.lstm_dir / "model_vul.pkl"
            vul_label_path = self.lstm_dir / "label_encoder_vul.pkl"
            
            if vul_model_path.exists() and vul_label_path.exists():
                with open(vul_model_path, 'rb') as f:
                    self.vul_model_final = pickle.load(f)
                with open(vul_label_path, 'rb') as f:
                    self.vul_label_encoder_final = pickle.load(f)
                print("✅ Vulnerability model loaded successfully")
            else:
                print(f"❌ Vulnerability model not found: {vul_model_path}, {vul_label_path}")
            
            # CWE 분석 모델 로드 (다중 분류용)
            cwe_model_path = self.lstm_dir / "model_cwe.pkl"
            cwe_label_path = self.lstm_dir / "label_encoder_cwe.pkl"
            
            if cwe_model_path.exists() and cwe_label_path.exists():
                with open(cwe_model_path, 'rb') as f:
                    self.vul_model_full = pickle.load(f)
                with open(cwe_label_path, 'rb') as f:
                    self.vul_label_encoder_full = pickle.load(f)
                print("✅ CWE model loaded successfully")
            else:
                print(f"❌ CWE model not found: {cwe_model_path}, {cwe_label_path}")
            
            # 악성 코드 분석 모델 로드 (평면 구조)
            mal_model_path = self.lstm_dir / "model_mal.pkl"
            mal_label_path = self.lstm_dir / "label_encoder_mal.pkl"
            
            if mal_model_path.exists() and mal_label_path.exists():
                with open(mal_model_path, 'rb') as f:
                    self.mal_model = pickle.load(f)
                with open(mal_label_path, 'rb') as f:
                    self.mal_label_encoder = pickle.load(f)
                print("✅ Malicious models loaded successfully")
            else:
                print(f"❌ Malicious models not found: {mal_model_path}, {mal_label_path}")
                
        except Exception as e:
            print(f"❌ Error loading models: {e}")
    
    def tokenize_python(self, code: str) -> List[str]:
        """Python 코드 토큰화 (공통 함수)"""
        # 간단한 토큰화 - 실제로는 더 정교한 전처리 필요
        tokens = re.findall(r'\b\w+\b', code)
        return tokens
    
    def embed_sequences(self, sequences: List[List[str]]) -> List[np.ndarray]:
        """시퀀스 임베딩 (공통 함수)"""
        if not self.w2v_model:
            return []
        
        embedded_sequences = []
        for sequence in sequences:
            embedded_sequence = []
            for token in sequence:
                if token in self.w2v_model.wv:
                    embedded_sequence.append(self.w2v_model.wv[token])
            if embedded_sequence:
                embedded_sequences.append(np.array(embedded_sequence))
        return embedded_sequences
    
    def pad_sequence(self, embedded_sequence: np.ndarray) -> np.ndarray:
        """시퀀스 패딩 (공통 함수)"""
        embedding_dim = self.w2v_model.vector_size
        padded_code = np.zeros((self.max_sequence_length, embedding_dim))
        
        if embedded_sequence.shape[0] > 0:
            padding_length = self.max_sequence_length - embedded_sequence.shape[0]
            if padding_length > 0:
                padding = np.zeros((padding_length, embedding_dim))
                padded_code = np.concatenate((embedded_sequence, padding), axis=0)
            else:
                padded_code = embedded_sequence[:self.max_sequence_length]
        
        return padded_code
    
    def analyze_vulnerability(self, content: str, file_path: str) -> Dict[str, Any]:
        """취약점 분석 (safepy_3) - 이진 분류 + 다중 분류"""
        try:
            if not all([self.vul_model_final, self.vul_label_encoder_final, self.w2v_model]):
                return {"is_vulnerable": False, "error": "Models not loaded"}
            
            # 전처리 (공통)
            tokenized_code = self.tokenize_python(content)
            embedded_code = self.embed_sequences([tokenized_code])
            
            if not embedded_code or len(embedded_code) == 0 or embedded_code[0].size == 0:
                return {"is_vulnerable": False, "error": "Could not embed code"}
            
            # 패딩 (공통)
            padded_code = self.pad_sequence(embedded_code[0])
            padded_code = np.expand_dims(padded_code, axis=0)
            
            # 1) 이진 분류 (취약/정상)
            prediction_final = self.vul_model_final.predict(padded_code)
            predicted_label = (prediction_final > 0.5).astype(int)[0][0]
            predicted_vulnerability_status = self.vul_label_encoder_final.inverse_transform([predicted_label])[0]
            
            # 2) 취약 시 다중분류로 CWE 라벨 추정
            if predicted_vulnerability_status == 1 and self.vul_model_full and self.vul_label_encoder_full:
                prediction_full = self.vul_model_full.predict(padded_code)
                predicted_cwe_index = np.argmax(prediction_full, axis=1)[0]
                predicted_cwe = self.vul_label_encoder_full.inverse_transform([predicted_cwe_index])[0]
                cwe_label = predicted_cwe
            else:
                cwe_label = 'Safe'
            
            is_vulnerable = predicted_vulnerability_status == 1
            
            result = {
                "is_vulnerable": is_vulnerable,
                "vulnerability_probability": float(prediction_final[0][0]),
                "vulnerability_status": "Vulnerable" if is_vulnerable else "Safe",
                "vulnerability_label": "Vulnerable" if predicted_vulnerability_status == 1 else "Safe",
                "cwe_label": cwe_label
            }
            
            return result
            
        except Exception as e:
            return {"is_vulnerable": False, "error": str(e)}
    
    def analyze_malicious(self, content: str, file_path: str) -> Dict[str, Any]:
        """악성 코드 분석 (safepy_3_malicious)"""
        try:
            if not all([self.mal_model, self.mal_label_encoder, self.w2v_model]):
                return {"is_malicious": False, "error": "Models not loaded"}
            
            # 전처리 (공통)
            tokenized_code = self.tokenize_python(content)
            embedded_code = self.embed_sequences([tokenized_code])
            
            if not embedded_code or len(embedded_code) == 0 or embedded_code[0].size == 0:
                return {"is_malicious": False, "error": "Could not embed code"}
            
            # 패딩 (공통)
            padded_code = self.pad_sequence(embedded_code[0])
            padded_code = np.expand_dims(padded_code, axis=0)
            
            # 악성 코드 예측
            prediction = self.mal_model.predict(padded_code)
            
            if prediction.ndim == 2 and prediction.shape[1] == 1:
                # Binary sigmoid
                malicious_probability = float(prediction[0][0])
                predicted_index = int((prediction > 0.5).astype(int)[0][0])
            else:
                # Multiclass softmax
                predicted_index = int(np.argmax(prediction, axis=1)[0])
                malicious_probability = float(prediction[0][predicted_index])
            
            decoded_label = self.mal_label_encoder.inverse_transform([predicted_index])[0]
            
            # 악성 여부 판단
            safe_aliases = {"Benign", "benign", "Not Vulnerable", "Normal", "Safe", "0", 0}
            is_safe = decoded_label in safe_aliases
            
            result = {
                "is_malicious": not is_safe,
                "malicious_probability": malicious_probability,
                "malicious_status": "malicious" if not is_safe else "Safe",
                "malicious_label": decoded_label
            }
            
            return result
            
        except Exception as e:
            return {"is_malicious": False, "error": str(e)}
    
    def analyze_single_file(self, content: str, file_path: str, mode: str = "both") -> Dict[str, Any]:
        """단일 파일 분석 - mode에 따라 취약/악성/둘다 수행

        Args:
            content: 파일 내용
            file_path: 파일 경로
            mode: 'both' | 'mal' | 'vul'
        """
        start_time = time.time()
        
        # 취약점 분석 (safepy_3)
        vul_result = self.analyze_vulnerability(content, file_path) if mode in ("both", "vul") else {"is_vulnerable": False}
        
        # 악성 코드 분석 (safepy_3_malicious)
        mal_result = self.analyze_malicious(content, file_path) if mode in ("both", "mal") else {"is_malicious": False}
        
        analysis_time = time.time() - start_time
        
        return {
            "file_path": file_path,
            "analysis_time": analysis_time,
            "vulnerability_analysis": vul_result,
            "malicious_analysis": mal_result,
            "is_safe": not (vul_result.get("is_vulnerable", False) or mal_result.get("is_malicious", False))
        }
    
    async def analyze_files_multiprocess(self, session_id: str, files: List[Dict[str, Any]], mode: str = "both") -> Dict[str, Any]:
        """다중 프로세스로 파일들 분석 (3개 프로세스 제한)"""
        return await asyncio.to_thread(self._analyze_files_multiprocess_sync, session_id, files, mode)

    def _analyze_files_multiprocess_sync(self, session_id: str, files: List[Dict[str, Any]], mode: str = "both") -> Dict[str, Any]:
        """실제 다중 프로세스 분석을 동기적으로 수행한다."""
        try:
            # 프로세스 풀 초기화
            if self.executor is None:
                self.executor = ProcessPoolExecutor(max_workers=MAX_WORKERS)

            # 파일들을 청크로 나누어 병렬 처리
            chunk_size = max(1, len(files) // MAX_WORKERS)
            file_chunks = [files[i:i + chunk_size] for i in range(0, len(files), chunk_size)]

            print(f"🚀 Starting multiprocess analysis for session {session_id}")
            print(f"📊 Processing {len(files)} files in {len(file_chunks)} chunks with {MAX_WORKERS} workers")

            # 병렬 분석 실행
            futures = []
            for i, chunk in enumerate(file_chunks):
                future = self.executor.submit(analyze_file_chunk_worker, chunk, session_id, i, str(self.models_dir), mode)
                futures.append(future)
                self.active_tasks[session_id] = self.active_tasks.get(session_id, []) + [future]

            # 결과 수집
            all_results: List[Dict[str, Any]] = []
            for future in as_completed(futures):
                try:
                    chunk_results = future.result()
                    all_results.extend(chunk_results)
                except Exception as e:
                    print(f"❌ Chunk analysis failed: {e}")
                    continue

            # 활성 작업에서 제거
            if session_id in self.active_tasks:
                del self.active_tasks[session_id]

            print(f"✅ Analysis completed for session {session_id}: {len(all_results)} files processed")
            return {
                "session_id": session_id,
                "total_files": len(files),
                "processed_files": len(all_results),
                "results": all_results,
                "status": "completed"
            }

        except Exception as e:
            print(f"❌ Multiprocess analysis failed for session {session_id}: {e}")
            return {
                "session_id": session_id,
                "total_files": len(files),
                "processed_files": 0,
                "results": [],
                "status": "failed",
                "error": str(e)
            }
    
    def get_active_tasks_count(self) -> int:
        """현재 활성 작업 수 반환"""
        return sum(len(tasks) for tasks in self.active_tasks.values())
    
    def cleanup(self):
        """리소스 정리 (서버 종료 시에만 호출)"""
        if self.executor:
            self.executor.shutdown(wait=True)
            self.executor = None
    
    def shutdown_executor(self):
        """프로세스 풀 종료 (서버 종료 시에만 호출)"""
        if self.executor:
            self.executor.shutdown(wait=True)
            self.executor = None

def analyze_file_chunk_worker(files: List[Dict[str, Any]], session_id: str, chunk_id: int, models_dir: str, mode: str = "both") -> List[Dict[str, Any]]:
    """파일 청크 분석 워커 (별도 프로세스에서 실행)

    mode: 'both' | 'mal' | 'vul'
    """
    results = []
    
    try:
        # 각 프로세스에서 분석기 생성
        analyzer = IntegratedLSTMAnalyzer(models_dir)
        
        print(f"🔍 Worker {chunk_id} processing {len(files)} files")
        
        for file_info in files:
            try:
                # 파일 내용이 있는지 확인
                if not file_info.get("content"):
                    print(f"⚠️ Empty content for file {file_info['path']}")
                    continue
                
                result = analyzer.analyze_single_file(file_info["content"], file_info["path"], mode=mode)
                result["session_id"] = session_id
                result["file_name"] = file_info["name"]
                result["file_size"] = file_info["size"]
                results.append(result)
                
            except Exception as e:
                print(f"❌ Error analyzing file {file_info['path']}: {e}")
                # 오류 시에도 기본 결과 생성
                results.append({
                    "session_id": session_id,
                    "file_path": file_info["path"],
                    "file_name": file_info["name"],
                    "file_size": file_info["size"],
                    "analysis_time": 0.0,
                    "vulnerability_analysis": {"is_vulnerable": False, "error": str(e)},
                    "malicious_analysis": {"is_malicious": False, "error": str(e)},
                    "is_safe": True
                })
        
        print(f"✅ Worker {chunk_id} completed: {len(results)} files analyzed")
        return results
        
    except Exception as e:
        print(f"❌ Worker {chunk_id} failed: {e}")
        return []

# 전역 분석기 인스턴스 (호환성용)
_global_analyzer = None

def get_global_analyzer():
    """전역 분석기 인스턴스 반환"""
    global _global_analyzer
    if _global_analyzer is None:
        _global_analyzer = IntegratedLSTMAnalyzer()
    return _global_analyzer

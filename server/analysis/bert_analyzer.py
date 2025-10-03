"""
BERT 기반 통합 분석기
CodeBERT 모델을 사용한 취약점 및 악성코드 분석
"""

import asyncio
import os
import sys
import time

try:  # pragma: no cover - optional dependency guard
    import torch  # type: ignore
except ImportError:  # pragma: no cover
    torch = None  # type: ignore

import numpy as np
from pathlib import Path
from typing import Dict, List, Any, Optional

try:  # pragma: no cover - optional dependency guard
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
except ImportError:  # pragma: no cover
    AutoTokenizer = None  # type: ignore
    AutoModelForSequenceClassification = None  # type: ignore

# 서버 디렉토리를 Python 경로에 추가
server_dir = Path(__file__).parents[1]
sys.path.insert(0, str(server_dir))

def load_labels(path: str) -> Optional[List[str]]:
    """텍스트 파일에서 라벨명을 줄 단위로 로드. 파일이 없으면 None.

    Args:
        path: 라벨 파일 경로

    Returns:
        라벨명 리스트 또는 None
    """
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            labels = [line.strip() for line in f if line.strip()]
        return labels or None
    except Exception:
        return None

class BERTAnalyzer:
    """BERT 기반 통합 분석기"""
    
    def __init__(self, models_dir: str):
        """
        BERT 분석기 초기화
        
        Args:
            models_dir: 모델 디렉토리 경로
        """
        if torch is None or AutoTokenizer is None or AutoModelForSequenceClassification is None:
            raise RuntimeError(
                "BERT analysis requires 'torch' and 'transformers' packages; install them to enable this feature."
            )

        self.models_dir = Path(models_dir)
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        
        # 모델 경로 설정
        # 1) 서버 내부 models 경로 우선
        mal_server = self.models_dir / "bert_mal" / "codebert"
        vul_server = self.models_dir / "bert_vul" / "codebert"
        # 2) 서버에 없으면 원본 레포 경로로 폴백
        mal_original = Path(__file__).parents[2] / "codebert_mal" / "model" / "codebert"
        vul_original = Path(__file__).parents[2] / "codebert_test2" / "model" / "codebert"
        self.mal_model_path = mal_server if mal_server.exists() else mal_original
        self.vul_model_path = vul_server if vul_server.exists() else vul_original
        
        # CWE 라벨 로딩
        cwe_labels_path = self.models_dir / "bert_vul" / "cwe_labels.txt"
        self.cwe_label_names = load_labels(str(cwe_labels_path))
        
        # 모델 및 토크나이저 초기화
        self.mal_tokenizer = None
        self.mal_model = None
        self.vul_tokenizer = None
        self.vul_model = None
        
        # 설정
        self.max_length = 512
        # 원본 파이프라인과 일치하도록 stride 조정
        self.stride = 64
        self.batch_size = 8
        self.threshold = 0.5
        # 긍정 클래스 인덱스 (이진: 1, 다중: id2label 기반 추정)
        self.mal_positive_index = 1
        self.vul_positive_index = 1
        
        print(f"🔧 BERT Analyzer initialized on {self.device}")
        print(f"📁 Malicious model path: {self.mal_model_path}")
        print(f"📁 Vulnerability model path: {self.vul_model_path}")
        print(f"📁 Models directory: {self.models_dir}")
        print(f"⚙️  Params - max_length={self.max_length}, stride={self.stride}, batch_size={self.batch_size}, threshold={self.threshold}")
    
    def load_malicious_model(self):
        """악성코드 분석 모델 로드"""
        try:
            if self.mal_model_path.exists():
                self.mal_tokenizer = AutoTokenizer.from_pretrained(str(self.mal_model_path))
                self.mal_model = AutoModelForSequenceClassification.from_pretrained(
                    str(self.mal_model_path), ignore_mismatched_sizes=True
                )
                self.mal_model.to(self.device)
                self.mal_model.eval()
                self.mal_positive_index = self._resolve_positive_index(self.mal_model, ["mal", "malicious"])  
                id2label = getattr(self.mal_model.config, "id2label", None)
                print(f"✅ Malicious BERT model loaded successfully (positive_index={self.mal_positive_index}, id2label={id2label})")
            else:
                print(f"⚠️ Malicious model not found at {self.mal_model_path}")
        except Exception as e:
            print(f"❌ Error loading malicious model: {e}")
    
    def load_vulnerability_model(self):
        """취약점 분석 모델 로드"""
        try:
            if self.vul_model_path.exists():
                self.vul_tokenizer = AutoTokenizer.from_pretrained(str(self.vul_model_path))
                self.vul_model = AutoModelForSequenceClassification.from_pretrained(
                    str(self.vul_model_path), ignore_mismatched_sizes=True
                )
                self.vul_model.to(self.device)
                self.vul_model.eval()
                self.vul_positive_index = self._resolve_positive_index(self.vul_model, ["vul", "vulnerable", "vulnerability"])  
                id2label = getattr(self.vul_model.config, "id2label", None)
                print(f"✅ Vulnerability BERT model loaded successfully (positive_index={self.vul_positive_index}, id2label={id2label})")
            else:
                print(f"⚠️ Vulnerability model not found at {self.vul_model_path}")
        except Exception as e:
            print(f"❌ Error loading vulnerability model: {e}")
    
    def analyze_malicious(self, content: str, file_path: str) -> Dict[str, Any]:
        """악성코드 분석"""
        if not self.mal_model or not self.mal_tokenizer:
            return {"is_malicious": False, "error": "Malicious model not loaded"}
        
        try:
            start_time = time.time()
            
            # 슬라이딩 윈도우로 청크 생성
            chunks = self._create_chunks(content)
            print(f"🧩 [MAL] Created {len(chunks)} chunks (max_length={self.max_length}, stride={self.stride}) for {file_path}")
            
            if not chunks:
                return {"is_malicious": False, "malicious_probability": 0.0, "malicious_status": "Safe", "malicious_label": "Safe"}
            
            # 배치 처리로 예측
            probabilities = []
            for i in range(0, len(chunks), self.batch_size):
                batch = chunks[i:i + self.batch_size]
                batch_probs = self._predict_batch(batch, self.mal_tokenizer, self.mal_model, self.mal_positive_index)
                probabilities.extend(batch_probs)
            
            # 파일 수준 확률 계산 (중앙 가중치 + 최댓값)
            file_probability = self._aggregate_probabilities(probabilities)
            print(f"📈 [MAL] Aggregated probability={file_probability:.4f} (pos_idx={self.mal_positive_index})")
            
            # 악성 여부 판단
            is_malicious = file_probability > self.threshold
            malicious_status = "malicious" if is_malicious else "Safe"
            malicious_label = "malicious" if is_malicious else "Safe"
            
            analysis_time = time.time() - start_time
            
            return {
                "is_malicious": is_malicious,
                "malicious_probability": file_probability,
                "malicious_status": malicious_status,
                "malicious_label": malicious_label,
                "analysis_time": analysis_time
            }
            
        except Exception as e:
            print(f"❌ Error in malicious analysis: {e}")
            return {"is_malicious": False, "error": str(e)}
    
    def analyze_vulnerability(self, content: str, file_path: str) -> Dict[str, Any]:
        """취약점 분석"""
        if not self.vul_model or not self.vul_tokenizer:
            return {"is_vulnerable": False, "error": "Vulnerability model not loaded"}
        
        try:
            start_time = time.time()
            
            # 슬라이딩 윈도우로 청크 생성
            chunks = self._create_chunks(content)
            print(f"🧩 [VUL] Created {len(chunks)} chunks (max_length={self.max_length}, stride={self.stride}) for {file_path}")
            
            if not chunks:
                return {"is_vulnerable": False, "vulnerability_probability": 0.0, "vulnerability_status": "Safe", "vulnerability_label": "Safe", "cwe_label": "Safe"}
            
            # 배치 처리로 예측
            probabilities = []
            for i in range(0, len(chunks), self.batch_size):
                batch = chunks[i:i + self.batch_size]
                batch_probs = self._predict_batch(batch, self.vul_tokenizer, self.vul_model, self.vul_positive_index)
                probabilities.extend(batch_probs)
            
            # 파일 수준 확률 계산
            file_probability = self._aggregate_probabilities(probabilities)
            print(f"📈 [VUL] Aggregated probability={file_probability:.4f} (pos_idx={self.vul_positive_index})")
            
            # 취약점 여부 판단
            is_vulnerable = file_probability > self.threshold
            vulnerability_status = "Vulnerable" if is_vulnerable else "Safe"
            vulnerability_label = "Vulnerable" if is_vulnerable else "Safe"
            
            # CWE 라벨 결정 (원본 코드 방식 참고)
            if is_vulnerable:
                # 모델의 id2label 확인
                id2label = getattr(self.vul_model.config, "id2label", None)
                if isinstance(id2label, dict):
                    id2label = {int(k): v for k, v in id2label.items()}
                
                # 가장 높은 확률을 가진 클래스의 인덱스 찾기
                max_prob_idx = np.argmax(probabilities) if probabilities else 0
                
                # CWE 라벨 매핑 (원본 코드의 idx_to_name 함수 로직)
                if self.cwe_label_names and 0 <= max_prob_idx < len(self.cwe_label_names):
                    cwe_label = self.cwe_label_names[max_prob_idx]
                elif id2label and max_prob_idx in id2label:
                    cwe_label = id2label[max_prob_idx]
                else:
                    cwe_label = f"class_{max_prob_idx}"
            else:
                cwe_label = "Safe"
            
            analysis_time = time.time() - start_time
            
            return {
                "is_vulnerable": is_vulnerable,
                "vulnerability_probability": file_probability,
                "vulnerability_status": vulnerability_status,
                "vulnerability_label": vulnerability_label,
                "cwe_label": cwe_label,
                "analysis_time": analysis_time
            }
            
        except Exception as e:
            print(f"❌ Error in vulnerability analysis: {e}")
            return {"is_vulnerable": False, "error": str(e)}
    
    def _create_chunks(self, content: str) -> List[str]:
        """슬라이딩 윈도우로 청크 생성"""
        if len(content) <= self.max_length:
            return [content]
        
        chunks = []
        start = 0
        while start < len(content):
            end = start + self.max_length
            chunk = content[start:end]
            chunks.append(chunk)
            start += self.max_length - self.stride
            
            if start >= len(content):
                break
        
        return chunks
    
    def _predict_batch(self, chunks: List[str], tokenizer, model, positive_index: int) -> List[float]:
        """배치 예측"""
        try:
            # 토크나이징
            inputs = tokenizer(
                chunks,
                padding=True,
                truncation=True,
                max_length=self.max_length,
                return_tensors="pt"
            )
            
            # GPU로 이동
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            # 예측
            with torch.no_grad():
                outputs = model(**inputs)
                logits = outputs.logits
                if logits.shape[-1] == 1:
                    probs = torch.sigmoid(logits).squeeze(-1).cpu().numpy()
                else:
                    probabilities = torch.softmax(logits, dim=-1)
                    probs = probabilities[:, positive_index].cpu().numpy()
            
            return probs.tolist()
            
        except Exception as e:
            print(f"❌ Error in batch prediction: {e}")
            return [0.0] * len(chunks)

    def _resolve_positive_index(self, model, keywords: List[str]) -> int:
        """모델 config에서 긍정 클래스 인덱스를 추론 (키워드 우선, 이진=1, 다중=마지막)."""
        try:
            config = getattr(model, "config", None)
            id2label = getattr(config, "id2label", None)
            if isinstance(id2label, dict) and len(id2label) > 0:
                for key, name in id2label.items():
                    try:
                        idx = int(key)
                    except Exception:
                        continue
                    if isinstance(name, str) and any(kw in name.lower() for kw in keywords):
                        return idx
            num_labels = getattr(config, "num_labels", None)
            if num_labels == 1:
                return 0
            if num_labels == 2:
                return 1
            return int(num_labels - 1) if num_labels else 1
        except Exception:
            return 1
    
    def _aggregate_probabilities(self, probabilities: List[float]) -> float:
        """확률 집계 (중앙 가중치 + 최댓값)"""
        if not probabilities:
            return 0.0
        
        # 중앙 가중치 계산 (n=1 케이스 보호)
        n = len(probabilities)
        if n == 1:
            weighted_avg = probabilities[0]
        else:
            weights = []
            for i in range(n):
                # 중앙에 가까울수록 높은 가중치
                distance_from_center = abs(i - (n-1)/2)
                denom = ((n-1)/2) if (n-1) != 0 else 1.0
                weight = 1.0 - (distance_from_center / denom)
                weights.append(max(0.1, weight))  # 최소 0.1
            # 가중 평균
            weighted_avg = sum(p * w for p, w in zip(probabilities, weights)) / max(1e-8, sum(weights))
        
        # 최댓값
        max_prob = max(probabilities)
        
        # 결합 (가중 평균 70% + 최댓값 30%)
        final_prob = 0.7 * weighted_avg + 0.3 * max_prob
        
        return float(final_prob)
    
    def analyze_single_file(self, content: str, file_path: str, mode: str = "both") -> Dict[str, Any]:
        """단일 파일 분석"""
        start_time = time.time()
        
        # 모드에 따라 분석 수행
        vul_result = self.analyze_vulnerability(content, file_path) if mode in ("both", "vul") else {"is_vulnerable": False}
        mal_result = self.analyze_malicious(content, file_path) if mode in ("both", "mal") else {"is_malicious": False}
        
        analysis_time = time.time() - start_time
        
        return {
            "file_path": file_path,
            "vulnerability_analysis": vul_result,
            "malicious_analysis": mal_result,
            "analysis_time": analysis_time,
            "is_safe": not (vul_result.get("is_vulnerable", False) or mal_result.get("is_malicious", False))
        }
    
    async def analyze_files_multiprocess(self, session_id: str, files: List[Dict[str, Any]], mode: str = "both") -> Dict[str, Any]:
        """다중 프로세스로 파일들 분석"""
        return await asyncio.to_thread(self._analyze_files_sync, session_id, files, mode)

    def _analyze_files_sync(self, session_id: str, files: List[Dict[str, Any]], mode: str = "both") -> Dict[str, Any]:
        try:
            print(f"🔍 Starting BERT multiprocess analysis for {len(files)} files (mode: {mode})")

            # 모델 로드
            if mode in ("both", "mal"):
                self.load_malicious_model()
            if mode in ("both", "vul"):
                self.load_vulnerability_model()

            results: List[Dict[str, Any]] = []
            total_files = len(files)

            for i, file_info in enumerate(files):
                try:
                    print(f"📄 Analyzing file {i+1}/{total_files}: {file_info['name']}")

                    if not file_info.get("content"):
                        print(f"⚠️ Empty content for file {file_info['path']}")
                        continue

                    result = self.analyze_single_file(file_info["content"], file_info["path"], mode=mode)
                    result["session_id"] = session_id
                    result["file_name"] = file_info["name"]
                    result["file_size"] = file_info["size"]

                    results.append(result)

                except Exception as e:
                    print(f"❌ Error analyzing file {file_info.get('name', 'unknown')}: {e}")
                    continue

            print(f"✅ BERT analysis completed: {len(results)} files processed")

            return {
                "status": "completed",
                "results": results,
                "total_files": len(results),
                "analysis_type": "BERT"
            }

        except Exception as e:
            print(f"❌ BERT multiprocess analysis failed: {e}")
            return {
                "status": "failed",
                "error": str(e),
                "results": [],
                "total_files": 0,
                "analysis_type": "BERT"
            }
    
    def get_active_tasks_count(self) -> int:
        """활성 작업 수 반환 (BERT는 단일 프로세스)"""
        return 0
    
    def shutdown_executor(self):
        """실행자 종료 (BERT는 단일 프로세스이므로 빈 구현)"""
        pass

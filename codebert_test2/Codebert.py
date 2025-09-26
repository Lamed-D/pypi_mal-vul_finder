"""
CodeBERT 기반 취약점/악성 분석 스크립트(실험용)

절차 개요:
1) source 폴더의 ZIP 추출 → 파이썬 파일(.py) 수집
2) 모델/토크나이저 로드
3) 슬라이딩 윈도우 청크로 추론 → 파일 레벨 확률 집계
4) CSV 저장(대시보드 최소 필드), 콘솔 요약 출력

본 파일은 실험/배치용으로, 서버 배포는 `server/analysis/lstm_analyzer.py`를 사용합니다.
"""

import os
import glob
import zipfile
import csv
import time
from datetime import datetime
from dataclasses import dataclass
from typing import List, Optional, Tuple

import torch
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# =========================
# Zero-config 기본 경로/설정
# =========================
CURRENT_DIR      = os.path.dirname(os.path.abspath(__file__))
SOURCE_DIR       = os.path.join(CURRENT_DIR, "source")   # *.zip 위치
MODEL_DIR        = os.path.join(CURRENT_DIR, "model", "codebert")
CWE_LABELS_PATH  = os.path.join(CURRENT_DIR, "model", "cwe_labels.txt")
LOG_DIR          = os.path.join(CURRENT_DIR, "logs")

MAX_LEN   = 512
STRIDE    = 128
BATCH_SZ  = 16  # GPU 메모리 허용 시 배치 크기 증가로 속도 향상
THRESHOLD = 0.50
DEVICE    = "cuda" if torch.cuda.is_available() else "cpu"

# =========================
# 유틸: ZIP 추출 / 파일 찾기 / 파일 읽기
# =========================
def extract_zip_files(source_dir: str) -> List[str]:
    """source_dir의 ZIP들을 같은 위치로 해제하고, 추출된 디렉토리 경로 목록을 반환.

    Args:
    	source_dir: ZIP 파일들이 있는 폴더

    Returns:
    	추출된 디렉토리 경로 리스트
    """
    extracted_dirs = []
    zip_files = glob.glob(os.path.join(source_dir, "*.zip"))
    for z in zip_files:
        try:
            name = os.path.splitext(os.path.basename(z))[0]
            dest = os.path.join(source_dir, name)
            os.makedirs(dest, exist_ok=True)
            with zipfile.ZipFile(z, "r") as ref:
                ref.extractall(dest)
            print(f"[OK] Extracted: {z} -> {dest}")
            extracted_dirs.append(dest)
        except Exception as e:
            print(f"[ERR] Extract {z}: {e}")
    return extracted_dirs

def find_python_files(directory: str) -> List[str]:
    """재귀적으로 디렉토리 내 .py 파일 경로를 수집.

    Args:
    	directory: 탐색 시작 디렉토리

    Returns:
    	파일 경로 리스트
    """
    py_files = []
    for root, _, files in os.walk(directory):
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))
    return py_files

def read_text(path: str) -> Optional[str]:
    """텍스트 파일을 UTF-8로 읽고, 실패 시 오류 무시 모드로 재시도.

    Args:
    	path: 파일 경로

    Returns:
    	텍스트 내용 또는 None
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        # 특수 인코딩 대비
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception as e:
            print(f"[ERR] Read {path}: {e}")
            return None

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

# =========================
# 모델/토크나이저 로드
# =========================
def load_unified_model(model_dir: str, device: str):
    """모델 디렉토리에서 토크나이저/분류 모델을 로드하고 device로 이동.

    Args:
    	model_dir: HF 포맷 모델 디렉토리
    	device: 'cpu' 또는 'cuda'

    Returns:
    	(tokenizer, model)
    """
    tok = AutoTokenizer.from_pretrained(model_dir)
    mdl = AutoModelForSequenceClassification.from_pretrained(model_dir)
    mdl.to(device)
    mdl.eval()
    
    # GPU 최적화: 컴파일 모드 활성화 (PyTorch 2.0+)
    if device == 'cuda' and hasattr(torch, 'compile'):
        try:
            mdl = torch.compile(mdl, mode='reduce-overhead')
            print("[GPU 최적화] torch.compile 활성화")
        except Exception as e:
            print(f"[GPU 최적화 실패] {e}")
    
    return tok, mdl

# =========================
# 보조: 안전(정상) 클래스 자동 추정
# =========================
SAFE_LABEL_HINTS = ["notvuln", "no_vuln", "no-vuln", "benign", "clean", "safe", "normal", "none"]
SAFE_CLASS_INDEX_OVERRIDE: Optional[int] = None  # 알면 여기 숫자(인덱스)로 지정

def find_safe_index(model) -> Optional[int]:
    """Infer the index of a 'safe/benign' class from model config labels."""
    if SAFE_CLASS_INDEX_OVERRIDE is not None:
        return SAFE_CLASS_INDEX_OVERRIDE
    id2label = getattr(model.config, "id2label", None)
    if not id2label:
        return None
    for k, v in id2label.items():
        name = str(v).lower().replace(" ", "").replace("-", "_")
        if any(h in name for h in SAFE_LABEL_HINTS):
            try:
                return int(k)
            except Exception:
                continue
    return None

# =========================
# 토크나이즈 + 슬라이딩 청크 생성 
# =========================
def chunk_with_overflow(tokenizer, text: str, max_len=512, stride=128):
    """긴 입력을 슬라이딩 윈도우로 커버하도록 토크나이즈.

    Returns:
    	input_ids/attention_mask를 가진 배치 텐서 딕셔너리
    """
    enc = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=max_len,
        padding=True,                      # 배치 스택 안전
        return_overflowing_tokens=True,
        stride=stride
    )
    return enc  # dict with input_ids, attention_mask

# =========================
# 단일 모델 추론: 취약도 + CWE Top-K
# - single_label(softmax)과 multi_label(sigmoid) 자동 대응
# =========================
@torch.no_grad()
def predict_unified(device, tokenizer, model, text: str,
                    max_len: int, stride: int, batch_sz: int, topk: int = 3):
    """청크 단위 추론 후 파일 레벨 메트릭 계산.

    Args:
    	device: 실행 디바이스
    	tokenizer, model: HF 구성 요소
    	text: 입력 소스코드
    	max_len, stride, batch_sz: 토크나이즈/배치 파라미터
    	topk: 상위 K개의 CWE 반환 개수

    Returns:
    	(vuln_prob, vulnerable_flag, top1_cwe, top1_prob, topk_list)
    """
    enc = chunk_with_overflow(tokenizer, text, max_len, stride)
    if enc["input_ids"].shape[0] == 0:
        return 0.0, 0, None, None, None  # (vuln_prob, vulnerable, top1_name, top1_prob, topk_named)

    # 배치 추론
    probs_all = []
    is_multilabel = (getattr(model.config, "problem_type", None) == "multi_label_classification")

    id2label = getattr(model.config, "id2label", None)
    # 있으면 cwe_labels.txt를 최우선으로 사용
    cwe_label_names = load_labels(CWE_LABELS_PATH)
    # transformers가 config.json을 로드할 때 id2label 키를 int로 캐스팅하기도 함
    if isinstance(id2label, dict):
        try:
            id2label = {int(k): v for k, v in id2label.items()}
        except Exception:
            pass
    def idx_to_name(i: int) -> str:
        if cwe_label_names and 0 <= i < len(cwe_label_names):
            return cwe_label_names[i]
        if id2label and i in id2label:
            return id2label[i]
        return f"class_{i}"

    for i in range(0, enc["input_ids"].shape[0], batch_sz):
        ids  = enc["input_ids"][i:i+batch_sz].to(device)
        mask = enc["attention_mask"][i:i+batch_sz].to(device)
        logits = model(input_ids=ids, attention_mask=mask).logits  # (B, C) or (B,1)

        if is_multilabel:
            p = torch.sigmoid(logits)                    # (B, C)
        else:
            if logits.shape[-1] == 1:
                # 특이 케이스: 진짜 1차원 이진일 때
                p = torch.sigmoid(logits)                # (B,1)
            else:
                p = torch.softmax(logits, dim=-1)        # (B, C)
        probs_all.append(p.cpu().numpy())

    probs = np.concatenate(probs_all, axis=0)  # (num_chunks, 1 or C)
    C = probs.shape[1]

    # ===== 이진 모델(출력 1)일 때: 청크 확률의 최대값을 취약도 =====
    if C == 1:
        vuln_prob = float(probs.max())
        vulnerable = int(vuln_prob >= THRESHOLD)
        return vuln_prob, vulnerable, None, None, None

    # ===== 다중(라벨 수 >=2)일 때 =====
    # 청크 평균(파일 레벨 확률)
    mean_probs = probs.mean(axis=0)  # (C,)

    # 안전(정상) 클래스가 있다면: vuln_prob = 1 - P(safe)
    safe_idx = find_safe_index(model)
    if (not is_multilabel) and (safe_idx is not None) and 0 <= safe_idx < C:
        vuln_prob = float(1.0 - mean_probs[safe_idx])
        vulnerable = int(vuln_prob >= THRESHOLD)
    else:
        # 안전 클래스가 없거나 멀티라벨이면:
        # - 멀티라벨: 취약도 = max(mean_probs) (여러 CWE 동시 가능)
        # - 단일라벨(안전 미탐지): 취약도 = Top-1 확률
        vuln_prob = float(mean_probs.max())
        vulnerable = int(vuln_prob >= THRESHOLD)

    # Top-k CWE
    top_idx = mean_probs.argsort()[::-1][:topk]
    top_named = [(idx_to_name(int(i)), float(mean_probs[i])) for i in top_idx]

    # Top-1이 안전 클래스라면 2등을 CWE로 표시
    cwe_top1_name, cwe_top1_prob = None, None
    if safe_idx is not None and int(top_idx[0]) == int(safe_idx) and len(top_idx) > 1:
        cwe_top1_name, cwe_top1_prob = idx_to_name(int(top_idx[1])), float(mean_probs[top_idx[1]])
    else:
        cwe_top1_name, cwe_top1_prob = idx_to_name(int(top_idx[0])), float(mean_probs[top_idx[0]])

    return vuln_prob, vulnerable, cwe_top1_name, cwe_top1_prob, top_named

# =========================
# 결과 구조
# =========================
@dataclass
class FileResult:
    file_path: str
    vulnerable_prob: float
    vulnerable: int
    cwe_top1: Optional[str] = None
    cwe_top1_prob: Optional[float] = None
    cwe_topk: Optional[List[Tuple[str, float]]] = None
    note: Optional[str] = None
    analysis_time: Optional[float] = None  # 분석 소요 시간 (초)
    
    @property
    def file_name(self) -> str:
        return os.path.basename(self.file_path)
    
    @property
    def vulnerability_status(self) -> str:
        return "Vulnerable" if self.vulnerable else "Benign"
    
    @property
    def cwe_label(self) -> str:
        return self.cwe_top1 if self.cwe_top1 else "Benign"

# =========================
# 파일 하나 분석
# =========================
def analyze_python_code(path: str, device: str, tok, mdl,
                        max_len=512, stride=128, batch_sz=8, threshold=0.5) -> FileResult:
    """단일 파이썬 파일을 분석하여 구조화된 결과를 반환."""
    start_time = time.time()
    
    code = read_text(path)
    if code is None or not code.strip():
        analysis_time = time.time() - start_time
        return FileResult(file_path=path, vulnerable_prob=0.0, vulnerable=0, 
                         note="empty-or-decode-error", analysis_time=analysis_time)

    vuln_prob, vulnerable, cwe_name, cwe_prob, topk_named = predict_unified(
        device, tok, mdl, code, max_len, stride, batch_sz, topk=3
    )

    # 최종 임계값 적용(필요시 덮어쓰기)
    vulnerable = int(vuln_prob >= threshold)
    
    analysis_time = time.time() - start_time

    res = FileResult(file_path=path, vulnerable_prob=vuln_prob, vulnerable=vulnerable, 
                    analysis_time=analysis_time)
    if vulnerable and cwe_name is not None:
        res.cwe_top1 = cwe_name
        res.cwe_top1_prob = cwe_prob
        res.cwe_topk = topk_named
    return res

# =========================
# 로그 저장 함수
# =========================
def save_results_to_csv(results: List[FileResult], log_file_path: str):
    """대시보드용 최소 컬럼으로 압축된 CSV 저장."""
    with open(log_file_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['file_path', 'file_name', 'vulnerability_status', 'cwe_label']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for result in results:
            # 절대 경로를 상대 경로로 변환
            relative_path = os.path.relpath(result.file_path, os.path.dirname(log_file_path))
            writer.writerow({
                'file_path': relative_path,
                'file_name': result.file_name,
                'vulnerability_status': result.vulnerability_status,
                'cwe_label': result.cwe_label
            })

# =========================
# 메인
# =========================
def main():
    """엔드투엔드: ZIP 해제 → 파일 수집 → 추론 → CSV 저장 및 요약 출력."""
    total_start_time = time.time()
    print(f"[INFO] Device: {DEVICE}")

    # 0) 로그 디렉토리 생성
    os.makedirs(LOG_DIR, exist_ok=True)

    # 1) 단일 모델 로드
    print(f"[INFO] Loading model: {MODEL_DIR}")
    tok, mdl = load_unified_model(MODEL_DIR, DEVICE)

    # 2) ZIP 추출
    print("[INFO] Extracting ZIPs...")
    extracted = extract_zip_files(SOURCE_DIR)
    
    if not extracted:
        print(f"[WARN] No ZIP files found. Put *.zip under: {SOURCE_DIR}")
        return

    # 3) 모든 결과 수집
    all_results = []
    
    # 4) 파일 루프
    for d in extracted:
        print(f"\n=== Analyzing dir: {d} ===")
        py_files = find_python_files(d)
        if not py_files:
            print(f"[WARN] No .py files in {d}")
            continue

        for i, fp in enumerate(py_files, 1):
            print(f"[{i}/{len(py_files)}] {fp}")
            r = analyze_python_code(fp, DEVICE, tok, mdl,
                                    max_len=MAX_LEN, stride=STRIDE, batch_sz=BATCH_SZ, threshold=THRESHOLD)
            all_results.append(r)
            
            msg = f"    -> vuln_prob={r.vulnerable_prob:.3f} vulnerable={r.vulnerable}"
            if r.cwe_top1 is not None:
                msg += f" cwe_top1={r.cwe_top1}({r.cwe_top1_prob:.3f})"
            if r.note:
                msg += f" note={r.note}"
            print(msg)

    # 5) 결과를 CSV로 저장
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(LOG_DIR, f"vulnerability_analysis_{timestamp}.csv")
    
    print(f"\n[INFO] Saving results to: {log_file}")
    save_results_to_csv(all_results, log_file)
    
    # 6) 전체 실행 시간 계산
    total_time = time.time() - total_start_time
    
    # 7) 요약 통계
    total_files = len(all_results)
    vulnerable_files = sum(1 for r in all_results if r.vulnerable)
    safe_files = total_files - vulnerable_files
    
    print(f"\n=== 분석 완료 ===")
    print(f"총 파일 수: {total_files}")
    print(f"취약 파일: {vulnerable_files}")
    print(f"안전 파일: {safe_files}")
    print(f"결과 저장: {log_file}")
    print(f"전체 실행 시간: {total_time:.2f}초")

if __name__ == "__main__":
    os.makedirs(SOURCE_DIR, exist_ok=True)
    main()

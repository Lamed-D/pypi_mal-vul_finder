"""
CodeBERT 기반 악성 코드(패키지) 분석 스크립트

절차 개요:
1) 입력 ZIP/디렉토리 발견 → 필요 시 압축 해제
2) 파이썬 파일(.py) 수집
3) 모델 로드 및 토크나이즈(슬라이딩 윈도우)
4) 파일 단위로 악성 확률 산출 → 임계값으로 라벨링
5) CSV 리포트 저장

주의: 경로는 항상 이 파일 기준(BASE_DIR)으로 해석합니다.
"""

import json
import os
import zipfile
from pathlib import Path
from typing import List, Dict, Tuple

import numpy as np
import pandas as pd
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from rich.progress import Progress, BarColumn, TimeRemainingColumn
from rich.console import Console
import time

console = Console()

# Default configuration (no CLI required)
# Always resolve paths relative to this file's directory to avoid CWD issues
BASE_DIR = Path(__file__).parent.resolve()
SOURCE_DIR = BASE_DIR / "source"
MODEL_DIR = BASE_DIR / "model" / "codebert"
EXTRACT_DIR = BASE_DIR / "extracted_packages"
REPORT_DIR = BASE_DIR / "log"
THRESHOLD = 0.5
BATCH_SIZE = 8  # GPU 메모리 허용 시 배치 크기 증가로 속도 향상
MAX_LENGTH = 512
STRIDE = 64


def ensure_dirs(*paths: Path) -> None:
    """입력 경로(디렉토리)들을 생성 보장합니다.

    Args:
    	*paths: 생성 보장할 디렉토리 경로들

    Returns:
    	None
    """
    for p in paths:
        Path(p).mkdir(parents=True, exist_ok=True)


def unzip_archive(zip_path: Path, extract_dir: Path) -> Path:
    """ZIP 파일을 지정 폴더에 해제하고, 추출 경로를 반환합니다.

    Args:
    	zip_path: 해제할 ZIP 파일 경로
    	extract_dir: 내용을 해제할 대상 디렉토리

    Returns:
    	추출된 디렉토리 경로
    """
    assert zip_path.exists(), f"Zip not found: {zip_path}"
    ensure_dirs(extract_dir)
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(extract_dir)
    return extract_dir


def discover_targets(source_dir: Path, extract_dir: Path) -> List[Tuple[str, Path]]:
    """소스 폴더에서 대상 패키지(폴더 또는 ZIP)를 찾아 (이름, 경로) 목록을 반환합니다.

    - 디렉토리는 그대로 대상이 되며,
    - ZIP은 `extract_dir/<zip_stem>`으로 해제 후 대상이 됩니다.

    Args:
    	source_dir: 입력 ZIP/폴더가 위치한 디렉토리
    	extract_dir: ZIP 해제를 위한 루트 디렉토리

    Returns:
    	[(패키지명, 대상 루트경로)] 리스트
    """
    targets: List[Tuple[str, Path]] = []
    if not source_dir.exists():
        # 스크립트 자급자족을 위해 폴더가 없으면 생성
        ensure_dirs(source_dir)
        if not source_dir.exists():
            raise FileNotFoundError(f"Source dir not found: {source_dir}")
    for entry in sorted(source_dir.iterdir()):
        if entry.is_dir():
            targets.append((entry.name, entry))
        elif entry.is_file() and entry.suffix.lower() == ".zip":
            out_dir = extract_dir / entry.stem
            unzip_archive(entry, out_dir)
            targets.append((entry.stem, out_dir))
    return targets


def list_python_files(root: Path) -> List[Path]:
    """루트 경로 아래의 모든 .py 파일 경로를 수집합니다.

    Args:
    	root: 탐색을 시작할 최상위 디렉토리

    Returns:
    	파이썬 파일 경로 리스트
    """
    paths: List[Path] = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if fn.lower().endswith('.py'):
                paths.append(Path(dirpath) / fn)
    return paths


def read_text(path: Path) -> str:
    """텍스트 파일을 UTF-8 기준으로 읽습니다. 실패 시 빈 문자열을 반환합니다.

    Args:
    	path: 읽을 파일 경로

    Returns:
    	파일 내용 문자열 또는 ""
    """
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return ""


def chunk_tokens(tokenizer: AutoTokenizer, text: str, max_length: int, stride: int) -> List[Dict]:
    """긴 입력을 슬라이딩 윈도우 방식으로 토큰 청크로 분할합니다.

    Args:
    	tokenizer: HF 토크나이저
    	text: 입력 텍스트(소스코드)
    	max_length: 청크 최대 길이(토큰 수)
    	stride: 오버랩 길이(토큰 수)

    Returns:
    	[{"input_ids", "attention_mask", "offset"}] 리스트
    """
    encoded = tokenizer(text, truncation=False, return_offsets_mapping=True)
    input_ids = encoded["input_ids"]
    attention_mask = encoded.get("attention_mask", [1] * len(input_ids))
    total = len(input_ids)
    chunks: List[Dict] = []
    start = 0
    while start < total:
        end = min(start + max_length, total)
        chunk_ids = input_ids[start:end]
        chunk_mask = attention_mask[start:end]
        chunks.append({
            "input_ids": chunk_ids,
            "attention_mask": chunk_mask,
            "offset": (start, end),
        })
        if end == total:
            break
        start = end - stride if end - stride > 0 else end
    return chunks


def batched(iterable: List, n: int) -> List[List]:
    """리스트를 n개 단위 배치로 분할하는 제너레이터.

    Args:
    	iterable: 원본 리스트
    	n: 배치 크기

    Yields:
    	부분 리스트
    """
    for i in range(0, len(iterable), n):
        yield iterable[i:i + n]


def load_model(model_dir: Path, device: torch.device):
    """로컬 모델 디렉토리에서 토크나이저/모델을 로드합니다.

    Args:
    	model_dir: HF 포맷 모델 디렉토리
    	device: 실행 디바이스(cpu/cuda)

    Returns:
    	(tokenizer, model)
    """
    tokenizer = AutoTokenizer.from_pretrained(str(model_dir), local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        str(model_dir), local_files_only=True, torch_dtype=torch.float16 if device.type == 'cuda' else torch.float32
    )
    model.to(device)
    model.eval()
    
    # GPU 최적화: 컴파일 모드 활성화 (PyTorch 2.0+)
    if device.type == 'cuda' and hasattr(torch, 'compile'):
        try:
            model = torch.compile(model, mode='reduce-overhead')
            console.print("[green]GPU 최적화: torch.compile 활성화[/green]")
        except Exception as e:
            console.print(f"[yellow]GPU 최적화 실패: {e}[/yellow]")
    
    return tokenizer, model


def resolve_malicious_index(model) -> int:
    """모델 라벨 이름에서 'mal' 힌트를 찾아 악성 인덱스를 추정합니다. 이진이면 1을 우선.

    Args:
    	model: HF SequenceClassification 모델

    Returns:
    	악성 클래스 인덱스(int)
    """
    id2label = getattr(model.config, "id2label", None)
    if isinstance(id2label, dict) and len(id2label) > 0:
        for idx_str, name in id2label.items():
            try:
                idx = int(idx_str) if isinstance(idx_str, str) else int(idx_str)
            except Exception:
                continue
            if isinstance(name, str) and "mal" in name.lower():
                return idx
    num_labels = getattr(model.config, "num_labels", None)
    if num_labels == 2:
        return 1
    return int(num_labels - 1) if num_labels else 0


def compute_prob_malicious(logits: torch.Tensor, malicious_index: int) -> np.ndarray:
    """로지트에서 악성 확률만 추출합니다(이진: sigmoid, 다중: softmax).

    Args:
    	logits: 모델 출력 로지트 (B, C) 또는 (B, 1)
    	malicious_index: 다중 분류에서 악성 클래스 인덱스

    Returns:
    	악성 확률 배열(shape: B,)
    """
    if logits.shape[-1] == 1:
        probs = torch.sigmoid(logits).squeeze(-1).detach().cpu().numpy()
        return probs
    else:
        probs = torch.softmax(logits, dim=-1).detach().cpu().numpy()
        return probs[:, malicious_index]


def classify_text_chunks(model, tokenizer, device: torch.device, text: str, max_length: int, stride: int, batch_size: int, malicious_index: int) -> float:
    """텍스트를 청크 단위로 추론하여 파일 레벨 악성 확률(최대값)을 반환합니다.

    Args:
    	model: HF 모델
    	tokenizer: HF 토크나이저
    	device: 실행 디바이스
    	text: 입력 소스코드 문자열
    	max_length: 청크 최대 토큰 수
    	stride: 청크 간 오버랩 토큰 수
    	batch_size: 배치 크기
    	malicious_index: 다중 분류 시 악성 인덱스

    Returns:
    	파일 레벨 악성 확률(float)
    """
    chunks = chunk_tokens(tokenizer, text, max_length=max_length, stride=stride)
    if not chunks:
        return 0.0
    input_batches = []
    for ch in chunks:
        encoded = tokenizer.prepare_for_model(ch["input_ids"], attention_mask=ch["attention_mask"], truncation=True, max_length=max_length, return_tensors='pt')
        input_batches.append(encoded)
    probs: List[float] = []
    with torch.no_grad():
        for batch in batched(input_batches, batch_size):
            batch_inputs = {k: torch.nn.utils.rnn.pad_sequence([b[k].squeeze(0) for b in batch], batch_first=True) for k in batch[0]}
            batch_inputs = {k: v.to(device) for k, v in batch_inputs.items()}
            outputs = model(**batch_inputs)
            batch_probs = compute_prob_malicious(outputs.logits, malicious_index)
            probs.extend(batch_probs.tolist())
    return float(max(probs))


def analyze_files(extract_root: Path, tokenizer, model, device: torch.device, max_length: int, stride: int, batch_size: int, threshold: float, malicious_index: int) -> List[Dict]:
    """폴더 내 모든 .py 파일을 악성 확률로 평가하고 결과 리스트를 반환합니다.

    Args:
    	extract_root: 분석할 패키지 루트 디렉토리
    	tokenizer, model, device: 추론 구성 요소
    	max_length, stride, batch_size: 토크나이즈/배치 파라미터
    	threshold: 라벨링 임계값
    	malicious_index: 다중 분류 시 악성 인덱스

    Returns:
    	[{file_path, file_name, vulnerability_status, label}] 리스트
    """
    py_files = list_python_files(extract_root)
    results: List[Dict] = []
    with Progress(
        "{task.description}", BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%", TimeRemainingColumn(), transient=True
    ) as progress:
        task = progress.add_task("Classifying .py files", total=len(py_files))
        for p in py_files:
            text = read_text(p)
            prob_mal = classify_text_chunks(model, tokenizer, device, text, max_length, stride, batch_size, malicious_index)
            label = "malicious" if prob_mal >= threshold else "benign"
            results.append({
                "file_path": str(p.relative_to(extract_root)),
                "file_name": p.name,
                "vulnerability_status": prob_mal,
                "label": label,
            })
            progress.update(task, advance=1)
    return results


def write_csv(report_dir: Path, results: List[Dict]) -> None:
    """분석 결과를 CSV로 저장합니다.

    Args:
    	report_dir: CSV 저장 디렉토리
    	results: analyze_files() 결과 리스트

    Returns:
    	None
    """
    ensure_dirs(report_dir)
    df = pd.DataFrame(results, columns=["package", "file_path", "file_name", "vulnerability_status", "label"])
    df.sort_values(["label", "vulnerability_status"], ascending=[True, False], inplace=True)
    df.to_csv(report_dir / "report.csv", index=False)



def main():
    """엔드투엔드 파이프라인 실행: 대상 찾기 → 분석 → CSV 저장/요약 출력.

    환경 변수/CLI 없이, 상단 고정 상수와 현재 파일 기준 경로만 사용합니다.
    """
    # 작업 경로 보장
    ensure_dirs(SOURCE_DIR, EXTRACT_DIR, REPORT_DIR)
    console.print(f"[bold]Source dir[/bold]: {SOURCE_DIR}")
    console.print(f"[bold]Model dir[/bold]: {MODEL_DIR}")
    console.print(f"[bold]Extract dir[/bold]: {EXTRACT_DIR}")
    console.print(f"[bold]Log dir[/bold]: {REPORT_DIR}")

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    console.print(f"[bold]Device[/bold]: {device}")
    console.print(f"[bold]Threshold[/bold]: {THRESHOLD}")

    start_time = time.perf_counter()
    targets = discover_targets(SOURCE_DIR, EXTRACT_DIR)
    tokenizer, model = load_model(MODEL_DIR, device)
    malicious_index = resolve_malicious_index(model)
    id2label = getattr(model.config, "id2label", None)
    console.print(f"[bold]Label map[/bold]: {id2label if id2label else 'unknown'} | malicious_index={malicious_index}")

    all_results: List[Dict] = []
    for pkg_name, root in targets:
        console.print(f"[bold]Scanning[/bold]: {pkg_name} -> {root}")
        pkg_results = analyze_files(
            extract_root=root,
            tokenizer=tokenizer,
            model=model,
            device=device,
            max_length=MAX_LENGTH,
            stride=STRIDE,
            batch_size=BATCH_SIZE,
            threshold=THRESHOLD,
            malicious_index=malicious_index,
        )
        # 결과에 패키지명 주석 추가
        for r in pkg_results:
            r["package"] = pkg_name
        all_results.extend(pkg_results)

    write_csv(Path(REPORT_DIR), all_results)
    elapsed = time.perf_counter() - start_time

    # 요약 출력
    total_files = len(all_results)
    malicious_count = sum(1 for r in all_results if r["label"] == "malicious")
    benign_count = sum(1 for r in all_results if r["label"] == "benign")
    console.print(f"[bold]Files scanned[/bold]: {total_files}")
    console.print(f"[bold]Malicious[/bold]: {malicious_count}  |  [bold]Benign[/bold]: {benign_count}")
    console.print(f"[bold]Elapsed[/bold]: {elapsed:.2f}s")
    console.print("[green]Analysis complete. CSV written.[/green]")


if __name__ == "__main__":
	main()
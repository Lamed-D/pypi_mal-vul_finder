import json
import os
import zipfile
import hashlib
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
BATCH_SIZE = 8
MAX_LENGTH = 512
STRIDE = 64


def ensure_dirs(*paths: Path) -> None:
	for p in paths:
		Path(p).mkdir(parents=True, exist_ok=True)


def unzip_archive(zip_path: Path, extract_dir: Path) -> Path:
    assert zip_path.exists(), f"Zip not found: {zip_path}"
    ensure_dirs(extract_dir)
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(extract_dir)
    return extract_dir


def discover_targets(source_dir: Path, extract_dir: Path) -> List[Tuple[str, Path]]:
    targets: List[Tuple[str, Path]] = []
    if not source_dir.exists():
        # Create missing source dir to make the script self-contained
        ensure_dirs(source_dir)
        # If still not there (rare permission issues), raise
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
	paths: List[Path] = []
	for dirpath, _, filenames in os.walk(root):
		for fn in filenames:
			if fn.lower().endswith('.py'):
				paths.append(Path(dirpath) / fn)
	return paths


def read_text(path: Path) -> str:
	try:
		return path.read_text(encoding='utf-8', errors='replace')
	except Exception:
		return ""


def chunk_tokens(tokenizer: AutoTokenizer, text: str, max_length: int, stride: int) -> List[Dict]:
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
	for i in range(0, len(iterable), n):
		yield iterable[i:i + n]


def load_model(model_dir: Path, device: torch.device):
	tokenizer = AutoTokenizer.from_pretrained(str(model_dir), local_files_only=True)
	model = AutoModelForSequenceClassification.from_pretrained(
		str(model_dir), local_files_only=True, torch_dtype=torch.float16 if device.type == 'cuda' else torch.float32
	)
	model.to(device)
	model.eval()
	return tokenizer, model


def resolve_malicious_index(model) -> int:
	# Try to find the label whose name hints at "malicious"
	id2label = getattr(model.config, "id2label", None)
	if isinstance(id2label, dict) and len(id2label) > 0:
		for idx_str, name in id2label.items():
			try:
				idx = int(idx_str) if isinstance(idx_str, str) else int(idx_str)
			except Exception:
				continue
			if isinstance(name, str) and "mal" in name.lower():
				return idx
	# Fallback: if binary, assume index 1 is malicious
	num_labels = getattr(model.config, "num_labels", None)
	if num_labels == 2:
		return 1
	# Default to last index
	return int(num_labels - 1) if num_labels else 0


def compute_prob_malicious(logits: torch.Tensor, malicious_index: int) -> np.ndarray:
	if logits.shape[-1] == 1:
		probs = torch.sigmoid(logits).squeeze(-1).detach().cpu().numpy()
		return probs
	else:
		probs = torch.softmax(logits, dim=-1).detach().cpu().numpy()
		return probs[:, malicious_index]


def classify_text_chunks(model, tokenizer, device: torch.device, text: str, max_length: int, stride: int, batch_size: int, malicious_index: int) -> float:
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
	ensure_dirs(report_dir)
	df = pd.DataFrame(results, columns=["package", "file_path", "file_name", "vulnerability_status", "label"])
	df.sort_values(["label", "vulnerability_status"], ascending=[True, False], inplace=True)
	df.to_csv(report_dir / "report.csv", index=False)



def main():
	# Ensure required directories exist regardless of current working directory
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
		# annotate with package name
		for r in pkg_results:
			r["package"] = pkg_name
		all_results.extend(pkg_results)

	write_csv(Path(REPORT_DIR), all_results)
	elapsed = time.perf_counter() - start_time

	# Print summary counts
	total_files = len(all_results)
	malicious_count = sum(1 for r in all_results if r["label"] == "malicious")
	benign_count = sum(1 for r in all_results if r["label"] == "benign")
	console.print(f"[bold]Files scanned[/bold]: {total_files}")
	console.print(f"[bold]Malicious[/bold]: {malicious_count}  |  [bold]Benign[/bold]: {benign_count}")
	console.print(f"[bold]Elapsed[/bold]: {elapsed:.2f}s")
	console.print("[green]Analysis complete. CSV written.[/green]")


if __name__ == "__main__":
	main()
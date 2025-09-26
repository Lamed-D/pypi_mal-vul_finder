### Pipeline: codebert_test2

- "Input": zip files under `source/` containing Python projects.
- "Model": HuggingFace CodeBERT sequence classification (`model/codebert/`).

Flow
- Extract zips: `extract_zip_files(source_dir)` → list of extracted dirs
- Discover files: `find_python_files(extracted_dir)` → list of `.py`
- Read content: `read_text(path)`
- Tokenize/chunk: `chunk_with_overflow(tokenizer, text, MAX_LEN, STRIDE)`
- Infer: `predict_unified(device, tokenizer, model, text, ...)` →
  - Handles binary/multiclass/multilabel
  - Computes file-level vulnerability probability and top-k CWE labels
- Per-file result: `analyze_python_code(file, ...)` → `FileResult`
- Persist: `save_results_to_csv(results, LOG_PATH)`
- Entrypoint: `main()` wires everything and prints summary

Key Parameters
- `MAX_LEN=512`, `STRIDE=128`, `BATCH_SZ=8`, `THRESHOLD=0.50`, `DEVICE=auto`

Notes
- Safe-class autodetect via `find_safe_index` (id2label names contain hints).
- Labels come from `model/config.json` with optional override `model/cwe_labels.txt`.


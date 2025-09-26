## 파이프라인: codebert_test2 (CodeBERT 기반 취약/정상 + CWE Top-K)

### 개요
- 입력: `source/` 폴더의 파이썬 프로젝트 ZIP
- 모델: HuggingFace CodeBERT 시퀀스 분류(`model/codebert/`)

### 흐름
1) ZIP 추출: `extract_zip_files(source_dir)` → 추출 디렉터리 목록
2) 파일 찾기: `find_python_files(extracted_dir)` → `.py` 목록
3) 읽기: `read_text(path)`
4) 토크나이즈/청크: `chunk_with_overflow(tokenizer, text, MAX_LEN, STRIDE)`
5) 추론/집계: `predict_unified(device, tokenizer, model, text, ...)`
   - 이진/다중/멀티라벨 자동 대응, 안전 클래스 고려(`find_safe_index`)
6) 파일 결과: `analyze_python_code(file, ...)` → `FileResult`
7) 저장: `save_results_to_csv(results, LOG_PATH)`
8) 진입점: `main()` 전체 실행 및 요약 출력

### 주요 파라미터
- `MAX_LEN=512`, `STRIDE=128`, `BATCH_SZ=16`, `THRESHOLD=0.50`, `DEVICE=auto`

## 환경 요구사항
- **Python**: 3.8 ~ 3.11
- **PyTorch**: 2.1.2
- **Transformers**: 4.40.2
- **기타**: numpy==1.26.4

## 설치 방법
```bash
# 가상환경 생성 (권장)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 또는
venv\Scripts\activate     # Windows

# 의존성 설치
pip install -r requirements.txt
```

## 주의사항
- **GPU 메모리**: 배치 크기 16 사용 시 충분한 GPU 메모리 필요
- **모델 파일**: `model/codebert/` 디렉토리에 사전 훈련된 모델 필요
- **입력 형식**: `source/` 폴더에 ZIP 파일 배치
- **출력**: `logs/` 디렉토리에 결과 저장

## 트러블슈팅
- **CUDA 오류**: GPU 메모리 부족 시 `BATCH_SZ`를 8로 줄이기
- **모델 로딩 실패**: `model/codebert/` 디렉토리와 파일 존재 확인
- **Python 3.11 오류**: Python 3.10 이하 버전 사용 권장

## 결과 CSV 컬럼
- `file_path`: 파일 상대 경로
- `file_name`: 파일명 (예: main.py)
- `vulnerability_status`: 취약점 상태 ("Vulnerable" 또는 "Benign")
- `cwe_label`: CWE 라벨 (취약 시 구체적 CWE, 정상 시 "Benign")

## 출력 예시
```
file_path,file_name,vulnerability_status,cwe_label
src/main.py,main.py,Vulnerable,CWE-79
utils/helper.py,helper.py,Benign,Benign
```

## 성능 최적화
- **GPU 자동 감지**: CUDA 사용 가능 시 자동으로 GPU 사용
- **배치 크기**: 16 (GPU 메모리 허용 시 속도 향상)
- **PyTorch 2.0+ 최적화**: torch.compile(mode='reduce-overhead') 자동 적용
- **슬라이딩 윈도우**: 긴 파일도 효율적 처리 (MAX_LEN=512, STRIDE=128)
- **안전 클래스 자동 탐지**: 정확도 향상

### 참고
- 안전(정상) 클래스 자동 추정: `find_safe_index` (id2label 힌트 기반)
- 라벨명: `model/config.json`의 `id2label`, 있으면 `model/cwe_labels.txt`를 우선 사용
- 임계값 0.5 이상이면 "Vulnerable", 미만이면 "Benign"으로 분류됩니다.


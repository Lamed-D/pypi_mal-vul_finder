# CodeBERT 악성 패키지 분석 파이프라인

## 개요
`analyze_package.py`는 ZIP/디렉토리 형태의 파이썬 패키지를 받아 파일 단위 악성 확률을 계산하고 `log/report.csv`로 저장합니다.

## 절차
1. 입력 수집: `source/` 폴더에서 ZIP 또는 디렉토리를 탐색
2. 압축 해제: ZIP이면 `extracted_packages/<zipname>/`로 해제
3. 파일 수집: 대상 루트에서 모든 `.py` 파일 재귀 수집
4. 모델 로드: `model/codebert/`의 로컬 모델/토크나이저 로드
5. 토크나이즈: 최대 512 토큰, 스트라이드 64로 슬라이딩 윈도우 분할
6. 추론: 청크 배치(16)로 추론 후 악성 확률 계산(이진은 sigmoid, 다중은 softmax)
7. 집계: 파일 레벨 점수 = 청크 확률 최대값
8. 라벨링: 임계값 0.5 이상이면 `malicious`, 미만이면 `benign`
9. 리포트: `log/report.csv` 저장(패키지명, 파일경로, 파일명, 확률, 라벨)

## 주요 함수
- `discover_targets(source_dir, extract_dir)`
  - 입력 대상(폴더/ZIP) 탐색 및 필요 시 압축 해제
- `list_python_files(root)`
  - `.py` 파일 목록 수집
- `load_model(model_dir, device)`
  - 로컬 디렉토리에서 토크나이저/모델 로드
- `chunk_tokens(tokenizer, text, max_length, stride)`
  - 긴 텍스트를 토큰 청크로 분할
- `classify_text_chunks(model, tokenizer, device, text, max_length, stride, batch_size, malicious_index)`
  - 청크 추론 후 파일 레벨 악성 확률 산출
- `analyze_files(extract_root, ...)`
  - 디렉토리 내 모든 파일 분석
- `write_csv(report_dir, results)`
  - 결과 CSV 저장

## 환경 요구사항
- **Python**: 3.8 ~ 3.11
- **PyTorch**: 2.1.2
- **Transformers**: 4.40.2
- **기타**: accelerate==0.30.1, safetensors==0.4.2, numpy==1.26.4

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

## 실행
```bash
python analyze_package.py
```

## 주의사항
- **GPU 메모리**: 배치 크기 16 사용 시 충분한 GPU 메모리 필요
- **모델 파일**: `model/codebert/` 디렉토리에 사전 훈련된 모델 필요
- **입력 형식**: `source/` 폴더에 ZIP 파일 또는 디렉토리 배치
- **출력**: `log/report.csv`에 결과 저장

## 트러블슈팅
- **CUDA 오류**: GPU 메모리 부족 시 `BATCH_SIZE`를 8로 줄이기
- **모델 로딩 실패**: `model/codebert/` 디렉토리와 파일 존재 확인
- **Python 3.11 오류**: Python 3.10 이하 버전 사용 권장

## 결과 CSV 컬럼
- `package`: 패키지명 (ZIP 파일명 또는 폴더명)
- `file_path`: 파일 상대 경로 (패키지 루트 기준)
- `file_name`: 파일명 (예: main.py)
- `vulnerability_status`: 악성 확률 (0.0~1.0 부동소수점)
- `label`: 최종 판정 ("malicious" 또는 "benign")

## 출력 예시
```
package,file_path,file_name,vulnerability_status,label
test-package,src/main.py,main.py,0.85,malicious
test-package,utils/helper.py,helper.py,0.23,benign
```

## 성능 최적화
- **GPU 자동 감지**: CUDA 사용 가능 시 자동으로 GPU 사용
- **메모리 최적화**: CPU(float32), GPU(float16) 자동 선택
- **배치 크기**: 16 (GPU 메모리 허용 시 속도 향상)
- **PyTorch 2.0+ 최적화**: torch.compile(mode='reduce-overhead') 자동 적용
- **슬라이딩 윈도우**: 긴 파일도 효율적 처리 (MAX_LENGTH=512, STRIDE=64)

## 비고
- 모델 라벨에 "mal" 힌트가 있으면 해당 인덱스를 악성 클래스로 사용합니다. 이진 모델의 경우 기본적으로 index=1을 악성으로 가정합니다.
- 결과는 패키지 단위가 아닌 파일 단위이며, 파일 점수는 청크 확률의 최대값을 사용합니다.
- 임계값 0.5 이상이면 "malicious", 미만이면 "benign"으로 분류됩니다.


## CodeBERT 기반 파이썬 패키지 악성 여부 분석

이 프로젝트는 로컬에 저장된 CodeBERT 분류 모델을 사용해 ZIP 형태의 파이썬 패키지를 분석하고, 각 `.py` 파일의 악성 여부를 CSV로 저장합니다.

### 사전 준비
- Python 3.9+
- pip
- 로컬 모델 디렉토리: `model/codebert` (이미 제공됨)

### 의존성 설치
```bash
pip install -r requirements.txt
```

### 실행 방법
아래 명령만 실행하면 됩니다.
```bash
python analyze_package.py
```

스크립트는 다음을 수행합니다:
- `source/python-packages-1757595213589.zip` 압축을 `extracted_packages/`에 해제
- `model/codebert`에서 분류 모델 로드
- 모든 `.py` 파일의 악성 확률 계산
- 결과를 `log/report.csv`로 저장

### 기본 동작(변경 불가 옵션 없이 고정)
- 임계값(Threshold): 0.5 (≥ 0.5 이면 `malicious`)
- 최대 토큰: 512, 스트라이드: 64, 배치 크기: 8
- GPU 사용 가능 시 자동 사용, 아니면 CPU 사용

### CSV 스키마
- `file_path`: 패키지 루트 기준 파일 상대 경로
- `file_name`: 파일 이름
- `vulnerability_status`: 악성 확률(0~1 부동소수)
- `label`: `malicious` 또는 `benign`

### 참고
- 모델 헤드가 2 로짓이면 소프트맥스 기반으로 악성 확률을 계산하고, 1 로짓이면 시그모이드를 사용합니다.
- 파일이 길어 모델 입력 길이를 초과하는 경우, 토큰 단위 청크로 나누어 평가하고 각 파일의 최종 점수는 청크들 중 최대 악성 확률을 사용합니다.

# Python 패키지 보안 분석 파이프라인 (리팩토링 버전)

## 📋 개요

이 문서는 리팩토링된 Python 패키지 보안 분석 도구의 파이프라인을 설명합니다.

## 🏗️ 새로운 아키텍처

### 모듈 구조
```
safepy_3_malicious_ML/
├── 📄 main.py                    # 메인 실행 파일 (새로 작성)
├── 📄 config.py                  # 설정 관리 (새로 작성)
├── 📄 utils.py                   # 유틸리티 함수 (새로 작성)
├── 📄 analyzer.py                # 분석기 클래스 (새로 작성)
├── 📄 preprocess.py              # 전처리 모듈 (기존)
├── 📄 requirements.txt           # 의존성 목록
├── 📄 README.md                  # 프로젝트 설명서
├── 📄 pipeline.md                # 이 문서
├── 📄 final_unified_backup.py    # 기존 파일 백업
└── 📁 model/, w2v/, source/, result/  # 기존 디렉토리들
```

## 🔄 파이프라인 흐름

### 1. 초기화 단계
```python
# main.py
pipeline = SecurityAnalysisPipeline()
pipeline.initialize()
```

**수행 작업:**
- TensorFlow 최적화 설정
- 모델 로드 (LSTM, XGBoost, Word2Vec)
- 로깅 설정

### 2. 데이터 처리 단계
```python
results = pipeline.process_zip_file(zip_path)
```

**수행 작업:**
- ZIP 파일 추출
- Python 파일 검색
- 파일 내용 읽기
- 전처리 및 분석

### 3. 분석 단계
```python
# analyzer.py
analysis_result = self.analyzer.analyze_package(package_data)
```

**수행 작업:**
- LSTM 기반 취약점 분석
- XGBoost 기반 악성 코드 분석
- 특성 추출 및 전처리

### 4. 결과 생성 단계
```python
report = pipeline.generate_report(results)
pipeline.save_results(results, report)
```

**수행 작업:**
- 분석 결과 집계
- 리포트 텍스트 생성
- CSV 및 TXT 파일 저장

## 🛠️ 주요 개선사항

### 1. 모듈화
- **기존**: 1400+ 라인의 단일 파일
- **개선**: 기능별로 분리된 모듈들
  - `config.py`: 설정 관리
  - `utils.py`: 공통 유틸리티
  - `analyzer.py`: 분석 로직
  - `main.py`: 파이프라인 오케스트레이션

### 2. 설정 관리
```python
# config.py
BASE_DIR = Path(__file__).parent
LSTM_MODEL_PATH = MODEL_DIR / "model_mal.pkl"
MAX_SEQUENCE_LENGTH = 100
```

### 3. 에러 처리
```python
# utils.py
def read_python_file(file_path: str) -> Optional[str]:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        # 대체 인코딩 시도
    except Exception as e:
        logger.warning(f"파일 읽기 실패: {e}")
        return None
```

### 4. 로깅 시스템
```python
# 모든 모듈에서 일관된 로깅
logger = logging.getLogger(__name__)
logger.info("작업 완료")
logger.error("오류 발생")
```

### 5. 메모리 관리
```python
# utils.py
def cleanup_memory():
    gc.collect()
    logger.info("메모리 정리 완료")
```

## 🚀 실행 방법

### 기본 실행
```bash
python main.py
```

### 설정 변경
```python
# config.py에서 설정 수정
MAX_SEQUENCE_LENGTH = 150  # 시퀀스 길이 변경
BATCH_SIZE = 64           # 배치 크기 변경
```

## 📊 출력 파일

### 1. 분석 결과 (CSV)
- `package_vulnerability_analysis.csv`: 상세 분석 결과
- 컬럼: package_name, file_path, vulnerability_detected, confidence 등

### 2. 리포트 (TXT)
- `pypi_malicious_reason_report.txt`: 종합 분석 리포트
- 내용: 통계, 상세 결과, 권장사항

## 🔧 개발자 가이드

### 새로운 분석기 추가
```python
# analyzer.py
class SecurityAnalyzer:
    def analyze_new_feature(self, data):
        # 새로운 분석 로직 구현
        pass
```

### 새로운 유틸리티 함수 추가
```python
# utils.py
def new_utility_function():
    # 새로운 유틸리티 함수 구현
    pass
```

### 설정 추가
```python
# config.py
NEW_SETTING = "value"
```

## 🐛 트러블슈팅

### 1. 모델 로드 실패
- 모델 파일 경로 확인
- pickle 파일 무결성 검사

### 2. 메모리 부족
- `MEMORY_MANAGEMENT` 설정 조정
- 배치 크기 감소

### 3. 인코딩 오류
- `utils.read_python_file()`에서 자동 처리
- 수동으로 인코딩 지정 가능

## 📈 성능 최적화

### 1. TensorFlow 설정
```python
# config.py
TF_OPTIMIZATIONS = {
    "TF_CPP_MIN_LOG_LEVEL": "2",
    "TF_FORCE_GPU_ALLOW_GROWTH": "true"
}
```

### 2. 메모리 관리
```python
# config.py
MEMORY_MANAGEMENT = {
    "enable_gc": True,
    "gc_threshold": 1000
}
```

### 3. 배치 처리
```python
# config.py
BATCH_SIZE = 32  # 시스템에 맞게 조정
```

## 🔄 마이그레이션 가이드

### 기존 코드에서 새 코드로
1. `final_unified_backup.py` 참조
2. 새로운 모듈 구조 이해
3. 설정 파일 확인
4. 단계별 테스트

### 호환성
- 기존 모델 파일들 그대로 사용 가능
- 기존 데이터 형식 유지
- 출력 파일 형식 호환

## 📝 향후 계획

1. **웹 인터페이스 추가**
2. **실시간 분석 기능**
3. **더 많은 ML 모델 지원**
4. **분석 결과 시각화**
5. **API 서버 구축**
"""
ML 패키지 분석기 - LSTM + XGBoost 통합 분석
============================================

이 모듈은 safepy_3_malicious_ML의 기능을 server에 통합하여
LSTM 기반 취약점 분석과 XGBoost 기반 악성 패키지 판별을 수행합니다.

주요 기능:
- LSTM 모델을 사용한 취약점 분석
- XGBoost 모델을 사용한 악성 패키지 판별
- 메타데이터 기반 피처 엔지니어링
- 통합 분석 결과 생성

분석 프로세스:
1. ZIP 파일에서 패키지 데이터 추출
2. 메타데이터 파싱 및 전처리
3. LSTM 모델로 취약점 분석
4. XGBoost 모델로 악성 패키지 판별
5. 통합 결과 생성 및 DB 저장
"""

import os
import csv
import re
import zipfile
import pickle
try:  # pragma: no cover - optional dependency guard
    import numpy as np
except ImportError:  # pragma: no cover
    np = None  # type: ignore

try:  # pragma: no cover
    import pandas as pd
except ImportError:  # pragma: no cover
    pd = None  # type: ignore
import time
import math
try:  # pragma: no cover
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore
from typing import Optional, Dict, List, Tuple, Any
from collections import Counter
try:  # pragma: no cover
    from sklearn.preprocessing import StandardScaler, MinMaxScaler
except ImportError:  # pragma: no cover
    StandardScaler = None  # type: ignore
    MinMaxScaler = None  # type: ignore
from pathlib import Path
import shutil

# TensorFlow 경고 메시지 숨기기
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
import warnings
warnings.filterwarnings('ignore')

# LSTM 관련 import
try:
    import chardet
    HAS_CHARDET = True
except ImportError:
    HAS_CHARDET = False

try:  # pragma: no cover
    from tensorflow.keras import backend as K
except ImportError:  # pragma: no cover
    K = None  # type: ignore

# preprocess import 시 출력 메시지 임시 숨기기
import sys
from io import StringIO

# stdout을 임시로 리디렉션하여 Word2Vec 로드 메시지 숨기기
old_stdout = sys.stdout
sys.stdout = StringIO()
try:
    # safepy_3_malicious_ML의 preprocess 모듈 import
    sys.path.append(str(Path(__file__).parents[2] / "safepy_3_malicious_ML"))
    from preprocess import tokenize_python, embed_sequences, w2v_model
except ImportError:  # pragma: no cover
    tokenize_python = None  # type: ignore
    embed_sequences = None  # type: ignore
    w2v_model = None  # type: ignore
finally:
    sys.stdout = old_stdout

# Levenshtein distance import
try:
    from Levenshtein import distance as levenshtein_distance
except ImportError:
    def levenshtein_distance(a, b):
        return abs(len(a) - len(b))

class MLPackageAnalyzer:
    """ML 패키지 분석기 - LSTM + XGBoost 통합"""
    
    def __init__(self, models_dir: str = None):
        """ML 패키지 분석기 초기화"""
        missing_dependencies = []
        if np is None:
            missing_dependencies.append("numpy")
        if pd is None:
            missing_dependencies.append("pandas")
        if StandardScaler is None or MinMaxScaler is None:
            missing_dependencies.append("scikit-learn")
        if K is None:
            missing_dependencies.append("tensorflow")
        if requests is None:
            missing_dependencies.append("requests")
        if tokenize_python is None or embed_sequences is None or w2v_model is None:
            missing_dependencies.append("safepy_3_malicious_ML preprocess")

        if missing_dependencies:
            raise RuntimeError(
                "MLPackageAnalyzer requires additional dependencies: "
                + ", ".join(missing_dependencies)
                + ". Install optional ML components to enable this feature."
            )

        # 서버 내부 모델 디렉토리만 사용 (완전 독립적)
        self.server_models_root = Path(__file__).parents[1] / "models" / "ml_package"
        self.model_save_dir = self.server_models_root / "model"
        self.w2v_dir = self.server_models_root / "w2v"
        
        # 서버 내부 모델 파일 존재 확인
        self._verify_server_models()
        
        # 모델들
        self.lstm_model = None
        self.label_encoder = None
        self.xgboost_model = None
        self.w2v_model = None
        
        # 분석 결과
        self.meta_datas = []
        self.df = None
        self.lstm_results = None
        
        # 모델 로드
        self._load_models()


    def _verify_server_models(self) -> None:
        """서버 내부 모델 파일들이 모두 존재하는지 확인"""
        required_files = [
            self.model_save_dir / 'model_mal.pkl',
            self.model_save_dir / 'label_encoder_mal.pkl',
            self.server_models_root / 'xgboost_model.pkl',
            self.w2v_dir / 'word2vec_withString10-6-100.model'
        ]
        
        missing_files = []
        for file_path in required_files:
            if not file_path.exists():
                missing_files.append(str(file_path))
        
        if missing_files:
            raise RuntimeError(
                f"필수 모델 파일들이 서버에 없습니다: {', '.join(missing_files)}\n"
                f"서버를 완전히 독립적으로 만들려면 이 파일들을 server/models/ml_package/ 디렉토리에 복사해야 합니다."
            )
        
        print("✅ 서버 내부 모델 파일들이 모두 존재합니다.")
    
    def _load_models(self):
        """모든 ML 모델 로드"""
        try:
            # LSTM 모델 로드
            lstm_model_path = self.model_save_dir / 'model_mal.pkl'
            if lstm_model_path.exists():
                with open(lstm_model_path, 'rb') as f:
                    self.lstm_model = pickle.load(f)
                print("✅ LSTM 모델 로드 성공")
            else:
                print(f"❌ LSTM 모델을 찾을 수 없습니다: {lstm_model_path}")
            
            # 라벨 인코더 로드
            label_encoder_path = self.model_save_dir / 'label_encoder_mal.pkl'
            if label_encoder_path.exists():
                with open(label_encoder_path, 'rb') as f:
                    self.label_encoder = pickle.load(f)
                print("✅ 라벨 인코더 로드 성공")
            else:
                print(f"❌ 라벨 인코더를 찾을 수 없습니다: {label_encoder_path}")
            
            # XGBoost 모델 로드 (서버 내부만 사용)
            xgboost_model_path = self.server_models_root / 'xgboost_model.pkl'
            if xgboost_model_path.exists():
                with open(xgboost_model_path, 'rb') as f:
                    self.xgboost_model = pickle.load(f)
                print("✅ XGBoost 모델 로드 성공")
            else:
                print(f"❌ XGBoost 모델을 찾을 수 없습니다: {xgboost_model_path}")
            
            # Word2Vec 모델은 preprocess에서 이미 로드됨
            if w2v_model is not None:
                self.w2v_model = w2v_model
                print("✅ Word2Vec 모델 로드 성공")
            else:
                print("❌ Word2Vec 모델 로드 실패")
                
        except Exception as e:
            print(f"❌ 모델 로드 중 오류 발생: {e}")
    
    def remove_comments(self, code):
        """소스 코드에서 주석 제거"""
        # 여러 줄 주석 제거
        code = re.sub(r"'''(.*?)'''", '', code, flags=re.DOTALL)
        code = re.sub(r'"""(.*?)"""', '', code, flags=re.DOTALL)
        # 한 줄 주석 제거
        code = re.sub(r'#.*', '', code)
        return code
    
    def process_directory(self, root_path):
        """디렉토리를 처리하여 소스코드를 추출하고 병합"""
        rows = []
        
        # root_path 내부의 모든 하위 디렉터리 탐색
        for dir_name in os.listdir(root_path):
            dir_path = os.path.join(root_path, dir_name)
            if os.path.isdir(dir_path):
                merged_code = ''
                for root, _, files in os.walk(dir_path):
                    for file in files:
                        if file.endswith('.py'):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    raw_code = f.read()
                                    cleaned_code = self.remove_comments(raw_code)
                                    merged_code += cleaned_code + '\n'
                            except Exception as e:
                                print(f"⚠️ {file_path} 읽기 실패: {e}")
                if merged_code.strip():
                    rows.append([dir_name, merged_code.strip()])
        return rows
    
    def extract_zip_and_process_source(self, zip_file_path: str, extract_dir: str):
        """ZIP 파일 압축 해제 및 소스코드 처리"""
        if not os.path.exists(zip_file_path):
            print(f"Warning: ZIP 파일을 찾을 수 없습니다: {zip_file_path}")
            return None
        
        # 압축 해제
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        
        # 소스코드 처리
        root_path = os.path.join(extract_dir, 'source')
        if os.path.exists(root_path):
            data = self.process_directory(root_path)
            print(f"✅ 소스코드 추출 완료: {len(data)}개 디렉터리 처리됨")
            return data
        else:
            print(f"Warning: 소스 경로를 찾을 수 없습니다: {root_path}")
            return None
    
    def parse_name_email(self, text):
        """이름과 이메일 파싱"""
        match = re.match(r"(.*)<(.*@.*)>", text)
        if match:
            name = match.group(1).strip()
            email = match.group(2).strip()
            return name, email
        return None, None
    
    def parse_metadata(self, file_path):
        """메타데이터 파싱"""
        target_keys = {
            "name", "summary", "author", "author-email", "version",
            "maintainer", "maintainer-email"
        }
        metadata = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        key, value = map(str.strip, line.split(':', 1))
                        key_lower = key.lower()
                        
                        if key_lower in target_keys:
                            metadata[key_lower] = value
            
            # author가 없거나 값이 비어 있을 경우
            if not metadata.get("author"):
                if metadata.get("author-email"):
                    name, email = self.parse_name_email(metadata["author-email"])
                    if name and email:
                        metadata["author"] = name
                        metadata["author-email"] = email
            
            # author_email이 없거나 값이 비어 있을 경우
            if not metadata.get("author-email"):
                if metadata.get("maintainer-email") and metadata["maintainer-email"].strip():
                    metadata["author-email"] = metadata["maintainer-email"]
            
            # author가 없거나 값이 비어 있을 경우 → maintainer로 대체
            if not metadata.get("author"):
                if metadata.get("maintainer") and metadata["maintainer"].strip():
                    metadata["author"] = metadata["maintainer"]
                    
        except Exception as e:
            print(f"메타데이터 파싱 오류 {file_path}: {e}")
            
        return metadata
    
    def extract_and_parse_metadata(self, extract_dir: str):
        """메타데이터 추출 및 파싱"""
        metadata_dir = os.path.join(extract_dir, "metadata")
        
        if not os.path.exists(metadata_dir):
            print(f"Warning: 메타데이터 디렉토리를 찾을 수 없습니다: {metadata_dir}")
            return []
            
        meta_datas = []
        for file in os.listdir(metadata_dir):
            if file.endswith(".txt"):
                metadata_path = os.path.join(metadata_dir, file)
                metadata = self.parse_metadata(metadata_path)
                if metadata:
                    meta_datas.append(metadata)
        
        self.meta_datas = meta_datas
        print(f"✅ 메타데이터 파싱 완료: {len(meta_datas)}개")
        return meta_datas
    
    def get_pepy_downloads(self, package_name, api_key):
        """PePy.tech API를 사용하여 다운로드 수 조회"""
        url = f"https://api.pepy.tech/api/v2/projects/{package_name}"
        headers = {"X-API-Key": api_key}
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                return data.get("total_downloads", -1)
            else:
                return -1
        except Exception as e:
            return -1
    
    def download_unified(self, package_name):
        """통합된 다운로드 수 조회"""
        download_count = self.get_pepy_downloads(package_name, "0SRbc/jRFsHYxOShwIQ/N0jtrKf1syMW")
        if download_count == -1:
            download_count = 0  # API 접근이 불가능할 경우 0으로 설정
        return download_count
    
    def shannon_entropy(self, s):
        """문자열의 Shannon 엔트로피 계산"""
        if not s:
            return 0
        prob = [v / len(s) for v in Counter(s).values()]
        return -sum(p * math.log2(p) for p in prob)
    
    def is_valid_version(self, v):
        """버전 형식 검증"""
        return bool(re.match(r"^\d+\.\d+\.\d+$", str(v).strip()))
    
    def get_pypi_top_packages(self):
        """PyPI 상위 패키지 목록 가져오기"""
        try:
            url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.json"
            response = requests.get(url)
            data = response.json()
            return [pkg['project'] for pkg in data['rows']]
        except Exception as e:
            print(f"인기 패키지 목록 조회 실패: {e}")
            return []
    
    def extract_core_name(self, name):
        """핵심 단어 추출 (접두/접미어 제거)"""
        return re.split(r"[-_.]", name.lower())[0]
    
    def is_typo_like(self, pkg_name, legit_list):
        """오타 기반 유사성 판별"""
        name = self.extract_core_name(pkg_name)
        for legit in legit_list:
            legit_core = self.extract_core_name(legit)
            if levenshtein_distance(name, legit_core) == 1 and abs(len(name) - len(legit_core)) <= 1:
                return True
        return False
    
    def preprocess_metadata(self):
        """메타데이터 전처리"""
        # 다운로드 수 수집
        for meta_data in self.meta_datas:
            package_name = meta_data.get("name")
            if package_name:
                download_count = self.download_unified(package_name)
                meta_data["download"] = download_count
        
        # DataFrame 변환
        df = pd.DataFrame(self.meta_datas)
        
        # 기본 전처리
        df["download"] = df["download"].fillna(0).astype(int)
        df["download_log"] = df["download"].apply(lambda x: np.log1p(x))
        
        scaler = StandardScaler()
        df["download_scaled"] = scaler.fit_transform(df[["download_log"]])
        
        # 설명 분석
        df["summary"] = df["summary"].fillna("")
        df["summary_length"] = df["summary"].apply(len)
        df["summary_too_short"] = df["summary_length"] < 10
        df["summary_too_long"] = df["summary_length"] > 300
        df["summary_entropy"] = df["summary"].apply(self.shannon_entropy)
        df["summary_low_entropy"] = df["summary_entropy"] < 3.5
        
        # 버전 검증
        df["version_valid"] = df["version"].apply(self.is_valid_version)
        
        # 오타 기반 탐지
        pypi_packages = self.get_pypi_top_packages()
        df["is_typo_like"] = df["name"].apply(lambda x: self.is_typo_like(x, pypi_packages))
        
        # 추가 피처
        df["download_too_low"] = df["download_log"] < df["download_log"].quantile(0.05)
        df["download_too_high"] = df["download_log"] > df["download_log"].quantile(0.95)
        df["is_disposable"] = False
        
        # MinMaxScaler로 download_log 정규화
        scaler2 = MinMaxScaler()
        df["download_log_scaled"] = 1 - scaler2.fit_transform(df[["download_log"]])
        
        self.df = df
        return df
    
    def analyze_single_code(self, source_code, package_name):
        """단일 코드 LSTM 분석"""
        try:
            tokenized_code = tokenize_python(source_code)
            
            if not tokenized_code:
                return {
                    'vulnerability_status': 'Error',
                    'cwe_label': 'parsing_error',
                    'confidence': 0.0
                }
            
            if self.w2v_model is None:
                return {
                    'vulnerability_status': 'Error',
                    'cwe_label': 'model_error',
                    'confidence': 0.0
                }
            
            embedded_code = embed_sequences([tokenized_code], self.w2v_model)
            
            if not embedded_code or len(embedded_code) == 0 or embedded_code[0].size == 0:
                return {
                    'vulnerability_status': 'Error',
                    'cwe_label': 'embedding_error',
                    'confidence': 0.0
                }
            
            # 시퀀스 패딩
            max_sequence_length = 100
            embedding_dim = self.w2v_model.vector_size
            padded_code = np.zeros((max_sequence_length, embedding_dim))
            
            embedded_sequence = embedded_code[0]
            if embedded_sequence.shape[0] > 0:
                if embedded_sequence.shape[0] < max_sequence_length:
                    padded_code[:embedded_sequence.shape[0], :] = embedded_sequence
                else:
                    padded_code = embedded_sequence[:max_sequence_length, :]
            
            padded_code = np.expand_dims(padded_code, axis=0)
            
            # 모델 예측
            prediction = self.lstm_model.predict(padded_code, verbose=0)
            
            if prediction.ndim == 2 and prediction.shape[1] == 1:
                confidence = float(prediction[0][0])
                predicted_index = int((prediction > 0.5).astype(int)[0][0])
            else:
                predicted_index = int(np.argmax(prediction, axis=1)[0])
                confidence = float(prediction[0][predicted_index])
            
            try:
                decoded_label = self.label_encoder.inverse_transform([predicted_index])[0]
            except Exception as e:
                return {
                    'vulnerability_status': 'Error',
                    'cwe_label': 'label_decode_error',
                    'confidence': confidence
                }
            
            benign_aliases = {"Benign", "benign", "Not Vulnerable", "Normal", "Safe", "0", 0}
            is_vulnerable = decoded_label not in benign_aliases
            
            vulnerability_status = 'Vulnerable' if is_vulnerable else 'Not Vulnerable'
            cwe_label = str(decoded_label) if is_vulnerable else 'Benign'
            
            return {
                'vulnerability_status': vulnerability_status,
                'cwe_label': cwe_label,
                'confidence': confidence
            }
            
        except Exception as e:
            print(f"코드 분석 오류 ({package_name}): {e}")
            return {
                'vulnerability_status': 'Error',
                'cwe_label': 'analysis_error',
                'confidence': 0.0
            }
    
    def analyze_lstm_codes(self, source_data):
        """소스 데이터의 모든 코드를 LSTM으로 분석"""
        if not source_data:
            return None
            
        print(f"\n=== LSTM 분석 시작: {len(source_data)}개 패키지 ===")
        start_time = time.time()
        
        results = []
        
        for idx, (package_name, source_code) in enumerate(source_data):
            print(f"LSTM 분석 중 ({idx+1}/{len(source_data)}): {package_name}")
            
            if not source_code or str(source_code).strip() == '':
                result_row = {
                    'package': package_name,
                    'vulnerability_status': 'Error',
                    'cwe_label': 'Empty Code',
                    'confidence': 0.0
                }
            else:
                analysis_result = self.analyze_single_code(str(source_code), package_name)
                result_row = {
                    'package': package_name,
                    'vulnerability_status': analysis_result['vulnerability_status'],
                    'cwe_label': analysis_result['cwe_label'],
                    'confidence': analysis_result['confidence']
                }
            
            results.append(result_row)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        result_df = pd.DataFrame(results)
        
        print(f"\n=== LSTM 분석 완료 ===")
        print(f"총 소요 시간: {total_time:.2f}초")
        print(f"패키지당 평균 시간: {total_time/len(source_data):.2f}초")
        
        self.lstm_results = result_df
        return result_df
    
    def integrate_lstm_results(self):
        """LSTM 결과를 메인 DataFrame에 통합"""
        if self.lstm_results is None or self.df is None:
            print("LSTM 결과 또는 메인 DataFrame이 없습니다.")
            return False
            
        # LSTM 결과를 메인 DataFrame과 병합
        # vulnerability_status를 숫자로 변환
        vulnerability_map = {'Vulnerable': 1, 'Not Vulnerable': 0, 'Error': -1}
        self.lstm_results['vulnerability_status_numeric'] = self.lstm_results['vulnerability_status'].map(vulnerability_map)
        
        # CWE 라벨을 숫자로 변환 (간단한 방식)
        cwe_map = {'Benign': 0, 'Empty Code': -1, 'parsing_error': -1, 'model_error': -1, 
                   'embedding_error': -1, 'label_decode_error': -1, 'analysis_error': -1}
        
        # CWE 값들을 숫자로 매핑 (기타는 1로 설정)
        self.lstm_results['cwe_label_numeric'] = self.lstm_results['cwe_label'].apply(
            lambda x: cwe_map.get(x, 1) if x in cwe_map else 1
        )
        
        # 패키지 이름을 기준으로 병합
        merged_df = pd.merge(self.df, 
                            self.lstm_results[['package', 'vulnerability_status_numeric', 'cwe_label_numeric', 'confidence']], 
                            left_on='name', 
                            right_on='package', 
                            how='left')
        
        # 병합되지 않은 항목은 기본값으로 설정
        merged_df['vulnerability_status_numeric'] = merged_df['vulnerability_status_numeric'].fillna(0)
        merged_df['cwe_label_numeric'] = merged_df['cwe_label_numeric'].fillna(0)
        merged_df['confidence'] = merged_df['confidence'].fillna(0.0)
        
        # 새로운 피처 생성 (노이즈 추가된 버전)
        merged_df['vulnerability_status_noisy'] = merged_df['vulnerability_status_numeric']
        merged_df['cwe_label_noisy'] = merged_df['cwe_label_numeric'] 
        merged_df['threat_level_noisy'] = merged_df.apply(self.combined_threat, axis=1)
        merged_df['download_log_noisy'] = merged_df['download_log']  # XGBoost 모델이 기대하는 피처명
        
        self.df = merged_df
        return True
    
    def combined_threat(self, row):
        """위협 수준 계산"""
        vuln_status = row.get('vulnerability_status_numeric', 0)
        cwe_label = row.get('cwe_label_numeric', 0)
        
        if vuln_status == 1 and cwe_label == 1:
            return 2
        elif vuln_status == 1 or cwe_label == 1:
            return 1
        else:
            return 0
    
    def predict_malicious(self):
        """XGBoost 모델로 악성 패키지 예측"""
        if self.df is None:
            print("분석할 데이터가 없습니다.")
            return False
            
        if self.xgboost_model is None:
            print("XGBoost 모델이 로드되지 않았습니다.")
            return False
        
        # 피처 선택 (XGBoost 모델이 기대하는 피처명과 일치)
        features = [
            "is_disposable", 
            "summary_length", "summary_too_short", "summary_too_long",
            "summary_entropy", "summary_low_entropy", "version_valid",
            "is_typo_like",
            "download_log_noisy",  # XGBoost 모델이 기대하는 피처명
            "vulnerability_status_noisy", "threat_level_noisy", "cwe_label_noisy"
        ]
        
        # 누락된 피처가 있는지 확인
        available_features = [f for f in features if f in self.df.columns]
        missing_features = [f for f in features if f not in self.df.columns]
        
        if missing_features:
            print(f"누락된 피처: {missing_features}")
            # 누락된 피처를 기본값으로 채움
            for feature in missing_features:
                self.df[feature] = 0
        
        X = self.df[features]
        
        # 예측 수행
        try:
            self.df["is_malicious"] = self.xgboost_model.predict(X)
            print("악성 패키지 예측 완료")
            return True
        except Exception as e:
            print(f"예측 수행 중 오류: {e}")
            return False
    
    def generate_comprehensive_results(self):
        """통합 분석 결과 생성"""
        if self.df is None or 'is_malicious' not in self.df.columns:
            print("예측 결과가 없어서 통합 결과를 생성할 수 없습니다.")
            return None
        
        # 통합 결과 DataFrame 준비
        comprehensive_df = self.df.copy()
        
        # LSTM 결과와 병합
        if self.lstm_results is not None:
            lstm_merge_df = self.lstm_results[['package', 'vulnerability_status', 'cwe_label', 'confidence']].rename(columns={
                'vulnerability_status': 'lstm_vulnerability_status',
                'cwe_label': 'lstm_cwe_label', 
                'confidence': 'lstm_confidence'
            })
            
            comprehensive_df = pd.merge(comprehensive_df, lstm_merge_df, 
                                       left_on='name', right_on='package', 
                                       how='left', suffixes=('', '_lstm'))
            
            # 중복 컬럼 제거
            if 'package_lstm' in comprehensive_df.columns:
                comprehensive_df = comprehensive_df.drop('package_lstm', axis=1)
        
        # 최종 예측 결과 컬럼 이름 명확화
        if 'is_malicious' in comprehensive_df.columns:
            comprehensive_df = comprehensive_df.rename(columns={'is_malicious': 'xgboost_prediction'})
        
        # 중요한 컬럼들을 앞쪽으로 재배치
        priority_columns = [
            'name',  # 패키지 이름
            'xgboost_prediction',  # XGBoost 최종 예측
            'lstm_vulnerability_status',  # LSTM 취약점 상태
            'lstm_cwe_label',  # LSTM CWE 라벨
            'lstm_confidence',  # LSTM 신뢰도
            'summary',  # 패키지 설명
            'author',  # 작성자
            'author-email',  # 작성자 이메일
            'version',  # 버전
            'download',  # 다운로드 수
            'download_log',  # 로그 변환된 다운로드 수
        ]
        
        # 우선순위 컬럼들이 존재하는 것만 선택
        available_priority_cols = [col for col in priority_columns if col in comprehensive_df.columns]
        
        # 나머지 컬럼들
        remaining_cols = [col for col in comprehensive_df.columns if col not in available_priority_cols]
        
        # 컬럼 순서 재정렬
        final_columns = available_priority_cols + remaining_cols
        comprehensive_df = comprehensive_df[final_columns]
        
        return comprehensive_df
    
    def analyze_package_zip(self, zip_file_path: str, extract_dir: str) -> Dict[str, Any]:
        """ZIP 파일을 통한 패키지 분석 (메인 함수)"""
        try:
            print("=== ML 패키지 분석 시작 ===")
            start_time = time.time()
            
            # 1. ZIP 파일 해제 및 소스코드 추출
            print("1️⃣ ZIP 파일 해제 및 소스코드 추출...")
            source_data = self.extract_zip_and_process_source(zip_file_path, extract_dir)
            if source_data is None:
                return {"error": "소스코드 추출 실패"}
            
            # 2. 메타데이터 추출 및 파싱
            print("2️⃣ 메타데이터 추출 및 파싱...")
            meta_data = self.extract_and_parse_metadata(extract_dir)
            if not meta_data:
                return {"error": "메타데이터 추출 실패"}
            
            # 3. 메타데이터 전처리
            print("3️⃣ 메타데이터 전처리...")
            df = self.preprocess_metadata()
            if df is None:
                return {"error": "메타데이터 전처리 실패"}
            
            # 4. LSTM 코드 분석
            print("4️⃣ LSTM 코드 분석...")
            lstm_results = self.analyze_lstm_codes(source_data)
            if lstm_results is None:
                return {"error": "LSTM 분석 실패"}
            
            # 5. LSTM 결과 통합
            print("5️⃣ LSTM 결과 통합...")
            if not self.integrate_lstm_results():
                return {"error": "결과 통합 실패"}
            
            # 6. XGBoost 악성 예측
            print("6️⃣ XGBoost 악성 패키지 예측...")
            if not self.predict_malicious():
                return {"error": "XGBoost 예측 실패"}
            
            # 7. 통합 결과 생성
            print("7️⃣ 통합 분석 결과 생성...")
            comprehensive_results = self.generate_comprehensive_results()
            if comprehensive_results is None:
                return {"error": "통합 결과 생성 실패"}
            
            end_time = time.time()
            total_time = end_time - start_time
            
            print(f"\n✅ ML 패키지 분석 완료! (총 소요 시간: {total_time:.2f}초)")
            
            # 결과를 딕셔너리 리스트로 변환
            results_list = comprehensive_results.to_dict('records')
            
            return {
                "success": True,
                "total_packages": len(results_list),
                "analysis_time": total_time,
                "results": results_list,
                "summary": {
                    "malicious_packages": sum(1 for r in results_list if r.get('xgboost_prediction', 0) == 1),
                    "vulnerable_packages": sum(1 for r in results_list if r.get('lstm_vulnerability_status') == 'Vulnerable'),
                    "safe_packages": sum(1 for r in results_list if r.get('xgboost_prediction', 0) == 0)
                }
            }
            
        except Exception as e:
            print(f"❌ ML 패키지 분석 중 오류 발생: {e}")
            return {"error": f"분석 중 오류 발생: {str(e)}"}
        finally:
            # 메모리 정리
            if K is not None:
                try:
                    K.clear_session()
                except Exception:
                    pass
    
    def analyze_extracted_files(self, extract_dir: str, extracted_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """추출된 파일들을 통한 패키지 분석 (서버 통합용)"""
        try:
            print("=== ML 패키지 분석 시작 (추출된 파일 사용) ===")
            start_time = time.time()
            
            # 1. 추출된 파일들에서 소스코드 데이터 생성
            print("1️⃣ 추출된 파일들에서 소스코드 데이터 생성...")
            print(f"📁 총 {len(extracted_files)}개 파일 처리 중...")
            source_data = []
            for i, file_info in enumerate(extracted_files):
                # file_service에서 반환하는 구조에 맞게 수정
                relative_path = file_info.get('path', '')
                file_name = file_info.get('name', '')
                content = file_info.get('content', '')
                
                if i < 5:  # 처음 5개 파일만 로그 출력
                    print(f"  📄 파일 {i+1}: {relative_path} ({len(content)} chars)")
                
                if file_name.endswith('.py') and content:
                    try:
                        cleaned_code = self.remove_comments(content)
                        if cleaned_code.strip():
                            # 패키지명 추출 (디렉토리 구조에서)
                            path_parts = Path(relative_path).parts
                            package_name = path_parts[0] if len(path_parts) > 0 else Path(file_name).stem
                            source_data.append({
                                "package_name": package_name,
                                "merged_code": cleaned_code.strip()
                            })
                    except Exception as e:
                        print(f"⚠️ 파일 처리 실패 {relative_path}: {e}")
                        continue
            
            print(f"✅ {len(source_data)}개 패키지의 소스코드 추출 완료")
            if not source_data:
                print("❌ 소스코드 추출 실패: 유효한 Python 파일이 없습니다")
                return {"error": "소스코드 추출 실패"}
            
            # 2. 메타데이터 추출 및 파싱
            print("2️⃣ 메타데이터 추출 및 파싱...")
            meta_data = self.extract_and_parse_metadata(extract_dir)
            if not meta_data:
                return {"error": "메타데이터 추출 실패"}
            
            # 3. 메타데이터 전처리
            print("3️⃣ 메타데이터 전처리...")
            df = self.preprocess_metadata()
            if df is None:
                return {"error": "메타데이터 전처리 실패"}
            
            # 4. LSTM 코드 분석
            print("4️⃣ LSTM 코드 분석...")
            lstm_results = self.analyze_lstm_codes(source_data)
            if lstm_results is None:
                return {"error": "LSTM 분석 실패"}
            
            # 5. LSTM 결과 통합
            print("5️⃣ LSTM 결과 통합...")
            if not self.integrate_lstm_results():
                return {"error": "결과 통합 실패"}
            
            # 6. XGBoost 악성 예측
            print("6️⃣ XGBoost 악성 패키지 예측...")
            if not self.predict_malicious():
                return {"error": "XGBoost 예측 실패"}
            
            # 7. 통합 결과 생성
            print("7️⃣ 통합 분석 결과 생성...")
            comprehensive_results = self.generate_comprehensive_results()
            if comprehensive_results is None:
                return {"error": "통합 결과 생성 실패"}
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # 결과를 서버 형식으로 변환
            results_list = []
            for _, row in comprehensive_results.iterrows():
                result_item = {
                    "name": row.get("name", ""),
                    "summary": row.get("summary", ""),
                    "author": row.get("author", ""),
                    "author-email": row.get("author-email", ""),
                    "version": row.get("version", ""),
                    "download": row.get("download", 0),
                    "lstm_vulnerability_status": row.get("lstm_vulnerability_status", "Not Vulnerable"),
                    "lstm_cwe_label": row.get("lstm_cwe_label", "N/A"),
                    "lstm_confidence": row.get("lstm_malicious_probability", 0.0),
                    "xgboost_prediction": int(row.get("xgboost_prediction", 0)),
                    "xgboost_confidence": float(row.get("xgboost_confidence", 0.0)),
                    "final_malicious_status": bool(row.get("xgboost_prediction", 0)),
                    "threat_level": 2 if row.get("xgboost_prediction", 0) == 1 else 0,
                    "analysis_time": 0.0
                }
                results_list.append(result_item)
            
            print(f"✅ ML 분석 완료: {len(results_list)}개 패키지 분석")
            
            return {
                "success": True,
                "analysis_time": total_time,
                "total_packages": len(results_list),
                "results": results_list,
                "summary": {
                    "malicious_packages": sum(1 for r in results_list if r.get('xgboost_prediction', 0) == 1),
                    "vulnerable_packages": sum(1 for r in results_list if r.get('lstm_vulnerability_status') == 'Vulnerable'),
                    "safe_packages": sum(1 for r in results_list if r.get('xgboost_prediction', 0) == 0)
                }
            }
            
        except Exception as e:
            print(f"❌ ML 패키지 분석 중 오류 발생: {e}")
            return {"error": f"분석 중 오류 발생: {str(e)}"}
        finally:
            # 메모리 정리
            if K is not None:
                try:
                    K.clear_session()
                except Exception:
                    pass

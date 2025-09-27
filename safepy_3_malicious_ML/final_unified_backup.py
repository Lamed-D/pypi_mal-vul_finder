"""
통합된 Python 패키지 보안 분석 도구 (Final Unified Version)

이 스크립트는 다음 기능들을 통합합니다:
1. 메타데이터 파일 파싱 후 리스트 형태로 저장
2. 모든 소스코드 추출 및 전처리
3. LSTM 기반 코드 취약점 분석
4. XGBoost 모델을 이용한 최종 악성 패키지 판단
5. 결과 리포트 생성

사용법:
    python final_unified.py

출력:
- merged_sourceCode.csv: 병합된 소스코드
- pypi_typo_analysis5.csv: 분석 결과 데이터
- package_vulnerability_analysis.csv: LSTM 분석 결과
- pypi_malicious_reason_report.txt: 최종 판단 리포트
"""

import os
import csv
import re
import zipfile
import pickle
import sys
import numpy as np
import pandas as pd
import gc
import math
import time
import requests
from typing import Optional, Dict, List, Tuple, Any
from collections import Counter
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from google.cloud import bigquery
from google.oauth2 import service_account
from google.api_core import exceptions as gcp_exceptions

# 경고 메시지 숨기기 및 성능 최적화
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # TensorFlow 경고 메시지 숨기기
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'  # oneDNN 최적화 비활성화
os.environ['TF_FORCE_GPU_ALLOW_GROWTH'] = 'true'  # GPU 메모리 점진적 할당
os.environ['TF_GPU_THREAD_MODE'] = 'gpu_private'  # GPU 스레드 모드 최적화
import warnings
warnings.filterwarnings('ignore')  # 모든 경고 메시지 숨기기

# TensorFlow GPU 메모리 최적화
try:
    import tensorflow as tf
    # GPU가 사용 가능한 경우 메모리 증가 허용
    gpus = tf.config.experimental.list_physical_devices('GPU')
    if gpus:
        try:
            for gpu in gpus:
                tf.config.experimental.set_memory_growth(gpu, True)
                tf.config.experimental.set_virtual_device_configuration(
                    gpu, [tf.config.experimental.VirtualDeviceConfiguration(memory_limit=1024)]
                )
        except RuntimeError:
            pass  # 이미 초기화된 경우 무시
except ImportError:
    pass

# LSTM 관련 import
try:
    import chardet
    HAS_CHARDET = True
except ImportError:
    HAS_CHARDET = False

# 케라스 import - 호환성을 위한 다중 방식 시도
try:
    from tensorflow.keras import backend as K
    from tensorflow import keras
except ImportError:
    try:
        import keras
        from keras import backend as K
    except ImportError:
        print("케라스 모듈을 찾을 수 없습니다. 호환 모드로 실행됩니다.")
        K = None
        keras = None

# preprocess import 시 출력 메시지 임시 숨기기
import sys
from io import StringIO

# stdout을 임시로 리디렉션하여 Word2Vec 로드 메시지 숨기기
old_stdout = sys.stdout
sys.stdout = StringIO()
try:
    from preprocess import tokenize_python, embed_sequences, w2v_model
finally:
    sys.stdout = old_stdout

# Levenshtein distance import (조용히 처리)
try:
    from Levenshtein import distance as levenshtein_distance
except ImportError:
    # 조용히 대체 함수 사용
    def levenshtein_distance(a, b):
        return abs(len(a) - len(b))  # 간단한 대체 함수

# Get the current directory
current_dir = os.path.dirname(os.path.abspath(__file__))
model_save_dir = os.path.join(current_dir, 'model')
result_dir = os.path.join(current_dir, 'result')

# Global variables for models
model_mal = None
label_encoder_mal = None
xgboost_model = None

class FinalUnifiedAnalyzer:
    def __init__(self):
        self.current_dir = current_dir
        self.model_save_dir = model_save_dir
        self.result_dir = result_dir
        self.meta_datas = []
        self.df = None
        self.lstm_results = None
        
    def read_python_file_with_encoding(self, file_path):
        """다양한 인코딩을 시도하여 Python 파일 읽기"""
        # 시도할 인코딩 리스트 (우선순위 순서)
        encodings = ['utf-8', 'utf-8-sig', 'cp949', 'euc-kr', 'latin-1', 'iso-8859-1', 'utf-16', 'ascii']
        
        # chardet으로 인코딩 감지 시도
        if HAS_CHARDET:
            try:
                with open(file_path, 'rb') as f:
                    raw_data = f.read(10000)  # 처음 10KB만 읽어서 감지
                    detected = chardet.detect(raw_data)
                    if detected['encoding'] and detected['confidence'] > 0.7:
                        detected_encoding = detected['encoding']
                        # 감지된 인코딩을 리스트 맨 앞으로
                        if detected_encoding not in encodings:
                            encodings.insert(0, detected_encoding)
                        elif encodings.index(detected_encoding) > 0:
                            encodings.remove(detected_encoding)
                            encodings.insert(0, detected_encoding)
                        print(f"[인코딩 감지] {file_path}: {detected_encoding} (신뢰도: {detected['confidence']:.2f})")
            except Exception as e:
                print(f"[인코딩 감지 실패] {file_path}: {e}")
        
        # 각 인코딩으로 파일 읽기 시도
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                    content = f.read()
                    # 성공적으로 읽었는지 확인 (replace 모드에서도 의미있는 내용인지)
                    if content.strip() and not ('�' in content and content.count('�') > len(content) * 0.1):
                        return content
            except (UnicodeDecodeError, UnicodeError):
                continue
            except Exception as e:
                print(f"⚠️ {file_path} 읽기 오류 ({encoding}): {e}")
                continue
        
        # 모든 인코딩 실패 시 바이너리 모드로 읽어서 ASCII 부분만 추출
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
                # ASCII 문자만 추출하여 기본적인 코드 구조 유지
                ascii_content = ''.join(chr(b) if 32 <= b <= 126 or b in [9, 10, 13] else ' ' for b in raw_data)
                if ascii_content.strip():
                    print(f"⚠️ {file_path}: ASCII 모드로 읽기 (일부 문자 손실 가능)")
                    return ascii_content
        except Exception as e:
            print(f"❌ {file_path}: 모든 읽기 방법 실패 - {e}")
        
        return None

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
                            raw_code = self.read_python_file_with_encoding(file_path)
                            if raw_code:
                                cleaned_code = self.remove_comments(raw_code)
                                merged_code += cleaned_code + '\n'
                if merged_code.strip():
                    rows.append([dir_name, merged_code.strip()])
        return rows

    def save_to_csv(self, data, output_file='merged_sourceCode.csv'):
        """데이터를 CSV 파일로 저장"""
        # result 폴더에 저장하도록 경로 수정
        if not os.path.isabs(output_file):
            os.makedirs(self.result_dir, exist_ok=True)
            output_file = os.path.join(self.result_dir, output_file)
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                # LSTM 분석과 호환되도록 컬럼명 통일
                writer.writerow(['package', 'code'])
                for row in data:
                    # 데이터 검증 후 저장
                    if len(row) >= 2 and row[1]:
                        writer.writerow([row[0], row[1]])
            print(f"✅ CSV 파일 저장 성공: {output_file}")
        except Exception as e:
            print(f"❌ CSV 파일 저장 실패: {e}")
            # 대체 인코딩으로 재시도
            try:
                with open(output_file, 'w', newline='', encoding='cp949') as f:
                    writer = csv.writer(f)
                    writer.writerow(['package', 'code'])
                    for row in data:
                        if len(row) >= 2 and row[1]:
                            writer.writerow([row[0], row[1]])
                print(f"✅ CSV 파일 저장 성공 (CP949): {output_file}")
            except Exception as e2:
                print(f"❌ CSV 파일 저장 최종 실패: {e2}")

    def extract_zip_and_process_source(self):
        """ZIP 파일 압축 해제 및 소스코드 처리 (강화된 오류 처리)"""
        zip_dir = "./python-packages-1757531529324.zip"
        extract_dir = "./extracted_files"
        
        if not os.path.exists(zip_dir):
            print(f"Warning: ZIP 파일을 찾을 수 없습니다: {zip_dir}")
            return None
        
        try:
            # 압축 해제
            print("🔄 ZIP 파일 압축 해제 중...")
            with zipfile.ZipFile(zip_dir, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            print(f"✅ ZIP 파일 압축 해제 완료: {extract_dir}")
        except Exception as e:
            print(f"❌ ZIP 파일 압축 해제 실패: {e}")
            return None
        
        # 소스코드 처리
        root_path = './extracted_files/source'
        if os.path.exists(root_path):
            print(f"🔍 소스코드 디렉토리 스캔: {root_path}")
            data = self.process_directory(root_path)
            
            if data:
                self.save_to_csv(data)
                print(f"✅ 소스코드 처리 완료: {len(data)}개 패키지")
                
                # 통계 정보 출력
                total_code_length = sum(len(row[1]) for row in data)
                avg_code_length = total_code_length / len(data) if data else 0
                print(f"📊 통계 - 총 코드 길이: {total_code_length:,} 문자, 평균: {avg_code_length:,.0f} 문자/패키지")
                
                return data
            else:
                print("⚠️ 처리된 소스코드가 없습니다.")
                return None
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
        """메타데이터 파싱 (다양한 인코딩 지원)"""
        target_keys = {
            "name", "summary", "author", "author-email", "version",
            "maintainer", "maintainer-email"
        }
        metadata = {}
        
        # 메타데이터 파일을 다양한 인코딩으로 읽기 시도
        content = self.read_metadata_file_with_encoding(file_path)
        if not content:
            return metadata

        try:
            for line in content.split('\n'):
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

    def read_metadata_file_with_encoding(self, file_path):
        """메타데이터 파일을 다양한 인코딩으로 읽기"""
        # 메타데이터 파일은 보통 ASCII/UTF-8이지만 다양한 인코딩 시도
        encodings = ['utf-8', 'utf-8-sig', 'ascii', 'latin-1', 'cp949', 'euc-kr', 'iso-8859-1']
        
        # chardet으로 인코딩 감지 시도
        if HAS_CHARDET:
            try:
                with open(file_path, 'rb') as f:
                    raw_data = f.read()
                    detected = chardet.detect(raw_data)
                    if detected['encoding'] and detected['confidence'] > 0.6:
                        detected_encoding = detected['encoding']
                        # 감지된 인코딩을 리스트 맨 앞으로
                        if detected_encoding not in encodings:
                            encodings.insert(0, detected_encoding)
                        elif encodings.index(detected_encoding) > 0:
                            encodings.remove(detected_encoding)
                            encodings.insert(0, detected_encoding)
            except Exception:
                pass
        
        # 각 인코딩으로 파일 읽기 시도
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                    content = f.read()
                    # replace 모드에서도 의미있는 내용인지 확인
                    if content.strip() and not ('\ufffd' in content and content.count('\ufffd') > len(content) * 0.1):
                        return content
            except Exception:
                continue
        
        print(f"⚠️ {file_path}: 메타데이터 읽기 실패 - 모든 인코딩 시도 실패")
        return None

    def extract_and_parse_metadata(self):
        """메타데이터 추출 및 파싱 (강화된 오류 처리)"""
        extract_dir = "./extracted_files"
        metadata_dir = os.path.join(extract_dir, "metadata")
        
        if not os.path.exists(metadata_dir):
            print(f"Warning: 메타데이터 디렉토리를 찾을 수 없습니다: {metadata_dir}")
            return []
        
        print(f"🔍 메타데이터 디렉토리 스캔: {metadata_dir}")
        meta_datas = []
        failed_files = []
        
        metadata_files = [f for f in os.listdir(metadata_dir) if f.endswith(".txt")]
        print(f"📁 발견된 메타데이터 파일: {len(metadata_files)}개")
        
        for file in metadata_files:
            metadata_path = os.path.join(metadata_dir, file)
            try:
                metadata = self.parse_metadata(metadata_path)
                if metadata and metadata.get('name'):  # 최소한 이름이 있는지 확인
                    meta_datas.append(metadata)
                else:
                    failed_files.append(f"{file} (파싱된 데이터 없음)")
            except Exception as e:
                failed_files.append(f"{file} ({str(e)})")
                print(f"⚠️ 메타데이터 파일 처리 실패: {file} - {e}")
        
        self.meta_datas = meta_datas
        
        # 결과 요약
        print(f"✅ 메타데이터 파싱 완료: {len(meta_datas)}개 성공")
        if failed_files:
            print(f"⚠️ 실패한 파일: {len(failed_files)}개")
            for fail in failed_files[:5]:  # 처음 5개만 출력
                print(f"   - {fail}")
            if len(failed_files) > 5:
                print(f"   ... 외 {len(failed_files) - 5}개 더")
        
        # 메타데이터 품질 검사
        if meta_datas:
            complete_metadata = sum(1 for md in meta_datas if all(md.get(key) for key in ['name', 'version', 'summary']))
            print(f"📊 완전한 메타데이터: {complete_metadata}/{len(meta_datas)}개")
        
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

    def get_download_count_bq(self, package_name, service_account_json):
        """BigQuery를 사용하여 다운로드 수 조회"""
        try:
            client = bigquery.Client.from_service_account_json(service_account_json)

            query = """
            SELECT COUNT(*) AS total_downloads
            FROM `bigquery-public-data.pypi.file_downloads`
            WHERE file.project = @pkg
            """

            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("pkg", "STRING", package_name)
                ]
            )

            query_job = client.query(query, job_config=job_config)
            result = query_job.result()

            for row in result:
                return int(row["total_downloads"])
            return 0
        except Exception as e:
            return -1

    def download_unified(self, package_name):
        """통합된 다운로드 수 조회"""
        """
        download_count = self.get_pepy_downloads(package_name, "0SRbc/jRFsHYxOShwIQ/N0jtrKf1syMW")
        if download_count == -1:
            download_count = self.get_download_count_bq(package_name, "./plated-mantis-471407-m4-b14f1b3e761d.json")    
        return download_count
        """
        return 0

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

    # LSTM 분석 관련 메서드들
    def detect_encoding(self, file_path):
        """파일 인코딩 감지"""
        if HAS_CHARDET:
            try:
                with open(file_path, 'rb') as f:
                    sample = f.read(10000)
                    result = chardet.detect(sample)
                    if result['confidence'] > 0.7:
                        return [result['encoding']]
            except Exception as e:
                print(f"인코딩 감지 오류: {e}")
        
        return ['cp949', 'euc-kr', 'utf-8', 'utf-16', 'latin-1', 'iso-8859-1']

    def read_csv_data(self, csv_file_path):
        """CSV 파일 읽기 (인코딩 자동 감지)"""
        print(f"CSV 파일 읽기 시도: {csv_file_path}")
        
        encodings = self.detect_encoding(csv_file_path)
        
        for encoding in encodings:
            try:
                print(f"인코딩 시도: {encoding}")
                df = pd.read_csv(csv_file_path, encoding=encoding)
                
                if 'package' not in df.columns or 'code' not in df.columns:
                    # Directory와 MergedCodeWithoutComments 컬럼이 있는 경우 변환
                    if 'Directory' in df.columns and 'MergedCodeWithoutComments' in df.columns:
                        df = df.rename(columns={'Directory': 'package', 'MergedCodeWithoutComments': 'code'})
                    else:
                        print(f"필요한 컬럼이 없습니다: {list(df.columns)}")
                        return None
                        
                print(f"CSV 파일 로드 성공: {csv_file_path} ({encoding})")
                print(f"행 수: {len(df)}, 컬럼: {list(df.columns)}")
                return df
                
            except UnicodeDecodeError:
                continue
            except Exception as e:
                print(f"CSV 읽기 오류 ({encoding}): {e}")
                continue
        
        print(f"모든 인코딩 시도 실패: {encodings}")
        return None

    def load_lstm_models(self):
        """LSTM 모델과 라벨 인코더 로드 - 반드시 기존 모델 사용"""
        global model_mal, label_encoder_mal
        
        try:
            model_path = os.path.join(self.model_save_dir, 'model_mal.pkl')
            
            # TensorFlow/Keras 호환성을 위한 설정
            import tensorflow as tf
            from tensorflow import keras
            import pickle
            try:
                import dill
                HAS_DILL = True
            except ImportError:
                HAS_DILL = False
            import sys
            
            print("기존 모델 파일 로드 중...")
            
            # Keras 호환성 처리를 위한 모듈 매핑
            def setup_keras_compatibility():
                """케라스 호환성을 위한 모듈 설정"""
                compatibility_mappings = {
                    'keras.src.models.sequential': 'keras.models',
                    'keras.src.models.model': 'keras.models', 
                    'keras.src.layers': 'keras.layers',
                    'keras.src.layers.core': 'keras.layers',
                    'keras.src.layers.dense': 'keras.layers',
                    'keras.src.layers.rnn': 'keras.layers',
                    'keras.src.layers.rnn.lstm': 'keras.layers',
                    'keras.src.layers.dropout': 'keras.layers',
                    'keras.src.optimizers': 'keras.optimizers',
                    'keras.src.optimizers.adam': 'keras.optimizers',
                    'keras.src.losses': 'keras.losses',
                    'keras.src.metrics': 'keras.metrics',
                    'keras.src.activations': 'keras.activations',
                    'keras.src.regularizers': 'keras.regularizers',
                    'keras.src.constraints': 'keras.constraints',
                    'keras.src.initializers': 'keras.initializers',
                    'keras.src.callbacks': 'keras.callbacks',
                    'keras.src.utils': 'keras.utils',
                    'keras.src.engine': 'keras.engine',
                    'keras.src.engine.sequential': 'keras.models',
                    'keras.src.saving': 'keras.utils'
                }
                
                old_modules = {}
                for old_path, new_path in compatibility_mappings.items():
                    if old_path not in sys.modules:
                        try:
                            # 새 모듈을 가져와서 이전 경로에 매핑
                            parts = new_path.split('.')
                            module = __import__(parts[0])
                            for part in parts[1:]:
                                if hasattr(module, part):
                                    module = getattr(module, part)
                                else:
                                    break
                            
                            sys.modules[old_path] = module
                            old_modules[old_path] = True
                            
                        except (ImportError, AttributeError) as e:
                            print(f"모듈 매핑 실패: {old_path} -> {new_path}: {e}")
                            pass
                            
                return old_modules
            
            # 방법 1: 호환성 설정 후 표준 pickle 로드
            print("방법 1: 호환성 매핑 + 표준 pickle")
            old_modules = setup_keras_compatibility()
            
            try:
                with open(model_path, 'rb') as f:
                    model_mal = pickle.load(f)
                print("✅ 호환성 매핑으로 기존 모델 로드 성공!")
                
            except Exception as e:
                print(f"❌ 호환성 매핑 + pickle 실패: {str(e)}")
                
                # 방법 2: Sequential 클래스 패치
                print("방법 2: Sequential 클래스 직접 패치")
                try:
                    from keras.models import Sequential
                    
                    # Sequential 클래스에 _unpickle_model 메서드 추가
                    if not hasattr(Sequential, '_unpickle_model'):
                        def _unpickle_model(cls, state):
                            model = cls()
                            model.__dict__.update(state)
                            return model
                        Sequential._unpickle_model = classmethod(_unpickle_model)
                    
                    with open(model_path, 'rb') as f:
                        model_mal = pickle.load(f)
                    print("✅ Sequential 패치로 기존 모델 로드 성공!")
                    
                except Exception as e:
                    print(f"❌ Sequential 패치 실패: {str(e)}")
                    
                    # 방법 3: dill 시도
                    print("방법 3: dill 로드")
                    try:
                        if not HAS_DILL:
                            raise ImportError("dill 패키지가 설치되지 않음")
                        with open(model_path, 'rb') as f:
                            model_mal = dill.load(f)
                        print("✅ dill로 기존 모델 로드 성공!")
                        
                    except Exception as e:
                        print(f"❌ dill 로드 실패: {str(e)}")
                        
                        # 방법 4: 케라스 네이티브 로드 시도
                        print("방법 4: Keras 네이티브 로드")
                        try:
                            # H5 또는 SavedModel 형식으로 저장된 모델이 있는지 확인
                            h5_path = model_path.replace('.pkl', '.h5')
                            savedmodel_path = model_path.replace('.pkl', '_savedmodel')
                            
                            if os.path.exists(h5_path):
                                model_mal = keras.models.load_model(h5_path)
                                print("✅ H5 형식으로 기존 모델 로드 성공!")
                            elif os.path.exists(savedmodel_path):
                                model_mal = keras.models.load_model(savedmodel_path)
                                print("✅ SavedModel 형식으로 기존 모델 로드 성공!")
                            else:
                                raise FileNotFoundError("H5 또는 SavedModel 파일을 찾을 수 없습니다.")
                                
                        except Exception as e:
                            print(f"❌ Keras 네이티브 로드 실패: {str(e)}")
                            
                            # 최후 방법: 직접 바이트 조작
                            print("방법 5: 직접 바이트 조작 시도")
                            try:
                                with open(model_path, 'rb') as f:
                                    data = f.read()
                                
                                # pickle 헤더에서 keras.src를 keras로 교체
                                modified_data = data.replace(b'keras.src.', b'keras.')
                                
                                # 임시 파일로 저장하고 로드
                                temp_path = model_path + '.temp'
                                with open(temp_path, 'wb') as f:
                                    f.write(modified_data)
                                
                                with open(temp_path, 'rb') as f:
                                    model_mal = pickle.load(f)
                                
                                os.remove(temp_path)  # 임시 파일 삭제
                                print("✅ 바이트 조작으로 기존 모델 로드 성공!")
                                
                            except Exception as e:
                                print(f"❌ 모든 방법 실패: {str(e)}")
                                raise Exception("기존 모델을 로드할 수 없습니다. 모든 시도 방법이 실패했습니다.")
            
            # 모듈 정리
            for module_name in old_modules:
                if module_name in sys.modules:
                    del sys.modules[module_name]
            
            # 모델 로드 확인
            if model_mal is None:
                raise Exception("모델 로드 후에도 model_mal이 None입니다.")
                
            print("✅ 기존 LSTM 모델 로드 완료!")
            print(f"모델 타입: {type(model_mal)}")
            
            # GPU 최적화 설정
            try:
                if tf.config.list_physical_devices('GPU'):
                    gpus = tf.config.experimental.list_physical_devices('GPU')
                    if gpus:
                        for gpu in gpus:
                            tf.config.experimental.set_memory_growth(gpu, True)
            except Exception:
                pass
            
        except Exception as e:
            print(f"LSTM 모델 로드 실패: {e}")
            return False
        
        # 라벨 인코더 로드
        try:
            encoder_path = os.path.join(self.model_save_dir, 'label_encoder_mal.pkl')
            with open(encoder_path, 'rb') as f:
                label_encoder_mal = pickle.load(f)
            print("라벨 인코더 로드 성공")
            return True
        except Exception as e:
            print(f"라벨 인코더 로드 실패: {e}")
            return False

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
            
            if w2v_model is None:
                return {
                    'vulnerability_status': 'Error',
                    'cwe_label': 'word2vec_error',
                    'confidence': 0.0
                }
            
            # 벡터 임베딩
            padded_code = embed_sequences([tokenized_code], w2v_model, max_length=100)
            
            if padded_code is None or len(padded_code) == 0:
                return {
                    'vulnerability_status': 'Error',
                    'cwe_label': 'embedding_error',
                    'confidence': 0.0
                }
            
            # LSTM 예측
            prediction = model_mal.predict(padded_code, verbose=0)
            
            if prediction is None or len(prediction) == 0:
                return {
                    'vulnerability_status': 'Error',
                    'cwe_label': 'prediction_error',
                    'confidence': 0.0
                }
            
            # 결과 해석
            predicted_class = np.argmax(prediction, axis=1)[0]
            confidence = float(np.max(prediction))
            
            # 라벨 인코더로 클래스 이름 변환
            if label_encoder_mal is not None:
                try:
                    cwe_label = label_encoder_mal.inverse_transform([predicted_class])[0]
                except Exception as e:
                    print(f"라벨 디코딩 오류: {e}")
                    cwe_label = f'class_{predicted_class}'
            else:
                cwe_label = f'class_{predicted_class}'
            
            # 취약점 상태 결정
            vulnerability_status = 'Vulnerable' if confidence > 0.5 else 'Safe'
            
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

    def analyze_lstm_codes(self, source_csv='merged_sourceCode.csv'):
        """CSV 파일의 모든 코드를 LSTM으로 분석 (메모리 최적화 포함)"""
        csv_path = os.path.join(self.result_dir, source_csv)  # result 폴더에서 찾도록 수정
        
        if not os.path.exists(csv_path):
            print(f"소스코드 CSV 파일을 찾을 수 없습니다: {csv_path}")
            return None
            
        df = self.read_csv_data(csv_path)
        if df is None:
            return None
        
        print(f"\n=== LSTM 분석 시작: {len(df)}개 패키지 ===")
        start_time = time.time()
        
        results = []
        
        for idx, row in df.iterrows():
            package_name = row['package']
            source_code = row['code']
            
            print(f"LSTM 분석 중 ({idx+1}/{len(df)}): {package_name}")
            
            if pd.isna(source_code) or str(source_code).strip() == '':
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
            
            # 주기적 메모리 정리 (10개 분석마다)
            if (idx + 1) % 10 == 0:
                try:
                    gc.collect()  # 가비지 컬렉션 실행
                    # Keras 세션 정리 (가능한 경우)
                    try:
                        K.clear_session()
                        print(f"[메모리 정리] {idx + 1}개 분석 완료 후 세션 정리")
                    except Exception:
                        pass
                except Exception:
                    pass
        
        end_time = time.time()
        total_time = end_time - start_time
        
        result_df = pd.DataFrame(results)
        
        # 최종 메모리 정리
        try:
            gc.collect()
            K.clear_session()
            print("[최종 정리] 메모리 및 세션 정리 완료")
        except Exception:
            pass
        
        print(f"\n=== LSTM 분석 완료 ===")
        print(f"총 소요 시간: {total_time:.2f}초")
        print(f"패키지당 평균 시간: {total_time/len(df):.2f}초")
        
        # 결과 저장
        os.makedirs(self.result_dir, exist_ok=True)
        output_path = os.path.join(self.result_dir, 'package_vulnerability_analysis.csv')
        result_df.to_csv(output_path, index=False, encoding='utf-8-sig')
        print(f"LSTM 분석 결과 저장: {output_path}")
        
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
        merged_df['download_log_scaled_noisy'] = merged_df['download_log_scaled']
        
        self.df = merged_df
        
        # 결과를 CSV로 저장 (result 폴더에)
        os.makedirs(self.result_dir, exist_ok=True)
        output_path = os.path.join(self.result_dir, 'pypi_typo_analysis5.csv')
        self.df.to_csv(output_path, index=False)
        print(f"통합된 분석 데이터 저장: {output_path}")
        
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

    def load_xgboost_model(self):
        """XGBoost 모델 로드"""
        global xgboost_model
        
        try:
            model_path = os.path.join(self.current_dir, "xgboost_model.pkl")
            with open(model_path, "rb") as f:
                xgboost_model = pickle.load(f)
            print("XGBoost 모델 로드 성공")
            return True
        except Exception as e:
            print(f"XGBoost 모델 로드 실패: {e}")
            return False

    def predict_malicious(self):
        """XGBoost 모델로 악성 패키지 예측"""
        if self.df is None:
            print("분석할 데이터가 없습니다.")
            return False
            
        if xgboost_model is None:
            print("XGBoost 모델이 로드되지 않았습니다.")
            return False
        
        # 피처 선택
        features = [
            "is_disposable", 
            "summary_length", "summary_too_short", "summary_too_long",
            "summary_entropy", "summary_low_entropy", "version_valid",
            "is_typo_like",
            "download_log_scaled_noisy",
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
            self.df["is_malicious"] = xgboost_model.predict(X)
            print("악성 패키지 예측 완료")
            print(self.df[["name", "is_malicious"]].head(10))
            return True
        except Exception as e:
            print(f"예측 수행 중 오류: {e}")
            return False

    def get_malicious_reasons(self, row):
        """악성 판단 이유 생성"""
        reasons = []
        if row.get("summary_too_short"): reasons.append("요약이 너무 짧음")
        if row.get("summary_too_long"): reasons.append("요약이 너무 김")
        if row.get("summary_low_entropy"): reasons.append("요약이 자동 생성된 것으로 의심됨")
        if row.get("download_too_low"): reasons.append("다운로드 수가 비정상적으로 낮음")
        if row.get("download_too_high"): reasons.append("다운로드 수가 비정상적으로 높음")
        if not row.get("version_valid"): reasons.append("버전 형식이 올바르지 않음")
        if row.get("is_disposable"): reasons.append("일회용 이메일 사용 의심")
        if row.get("is_typo_like"): reasons.append("인기 패키지 이름과 유사한 오타 기반 이름")
        if row.get("vulnerability_status_noisy", 0) == 1: reasons.append("LSTM 분석에서 취약점 발견")
        return reasons

    def get_normal_reasons(self, row):
        """정상 판단 이유 생성"""
        reasons = []
        if not row.get("summary_too_short"): reasons.append("요약 길이 적절함")
        if not row.get("summary_too_long"): reasons.append("요약이 너무 길지 않음")
        if not row.get("summary_low_entropy"): reasons.append("요약이 사람이 작성한 것으로 보임")
        if not row.get("download_too_low"): reasons.append("다운로드 수가 충분함")
        if not row.get("download_too_high"): reasons.append("다운로드 수가 과도하지 않음")
        if row.get("version_valid"): reasons.append("버전 형식이 올바름")
        if not row.get("is_disposable"): reasons.append("신뢰할 수 있는 이메일 사용")
        if not row.get("is_typo_like"): reasons.append("이름이 인기 패키지와 유사하지 않음")
        if row.get("vulnerability_status_noisy", 0) == 0: reasons.append("LSTM 분석에서 취약점 없음")
        return reasons

    def generate_final_report(self):
        """최종 분석 리포트 생성"""
        if self.df is None or 'is_malicious' not in self.df.columns:
            print("예측 결과가 없어서 리포트를 생성할 수 없습니다.")
            return False
        
        os.makedirs(self.result_dir, exist_ok=True)
        report_path = os.path.join(self.result_dir, "pypi_malicious_reason_report.txt")
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("=== Python 패키지 보안 분석 최종 리포트 ===\n\n")
            
            total_packages = len(self.df)
            malicious_count = self.df['is_malicious'].sum()
            normal_count = total_packages - malicious_count
            
            f.write(f"총 분석 패키지 수: {total_packages}\n")
            f.write(f"악성 패키지: {malicious_count}개\n")
            f.write(f"정상 패키지: {normal_count}개\n")
            f.write(f"악성 비율: {malicious_count/total_packages*100:.2f}%\n\n")
            
            for _, row in self.df.iterrows():
                pkg_name = row.get("name", "unknown")
                label = row.get("is_malicious", 0)

                if label == 1:
                    reasons = self.get_malicious_reasons(row)
                    status = "❌ 악성"
                else:
                    reasons = self.get_normal_reasons(row)
                    status = "✅ 정상"

                reason_text = " / ".join(reasons) if reasons else "판단 기준 없음"
                f.write(f"{status} 📦 {pkg_name}\n")
                f.write(f"→ 판단 이유: {reason_text}\n\n")

        print(f"📄 최종 분석 리포트 저장: {report_path}")
        return True

    def save_comprehensive_results(self):
        """모든 분석 결과를 포함한 통합 CSV 파일 생성"""
        if self.df is None:
            print("분석 결과가 없어서 통합 CSV를 생성할 수 없습니다.")
            return False
        
        # 결과 디렉토리 생성
        os.makedirs(self.result_dir, exist_ok=True)
        
        # 통합 결과 DataFrame 준비
        comprehensive_df = self.df.copy()
        
        # LSTM 결과와 병합 (이미 통합되어 있지만 명시적으로 표시)
        if self.lstm_results is not None:
            # LSTM 결과를 더 명확하게 표시
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
        
        # 통합 CSV 파일 저장
        comprehensive_csv_path = os.path.join(self.result_dir, 'comprehensive_analysis_results.csv')
        comprehensive_df.to_csv(comprehensive_csv_path, index=False, encoding='utf-8-sig')
        
        print(f"📊 통합 분석 결과 CSV 저장: {comprehensive_csv_path}")
        print(f"   - 총 패키지 수: {len(comprehensive_df)}")
        print(f"   - 총 컬럼 수: {len(comprehensive_df.columns)}")
        
        # 결과 요약 출력
        if 'xgboost_prediction' in comprehensive_df.columns:
            malicious_count = comprehensive_df['xgboost_prediction'].sum()
            print(f"   - XGBoost 예측 악성: {malicious_count}개")
            print(f"   - XGBoost 예측 정상: {len(comprehensive_df) - malicious_count}개")
        
        if 'lstm_vulnerability_status' in comprehensive_df.columns:
            lstm_vulnerable = (comprehensive_df['lstm_vulnerability_status'] == 'Vulnerable').sum()
            print(f"   - LSTM 취약점 발견: {lstm_vulnerable}개")
        
        # 주요 컬럼 목록 출력
        print("   - 주요 컬럼들:")
        for i, col in enumerate(available_priority_cols[:10]):  # 처음 10개만 출력
            print(f"     {i+1}. {col}")
        
        if len(available_priority_cols) > 10:
            print(f"     ... 외 {len(final_columns) - 10}개 컬럼")
        
        return comprehensive_csv_path

    def cleanup(self):
        """메모리 정리"""
        global model_mal, label_encoder_mal, xgboost_model
        
        try:
            K.clear_session()
        except:
            pass
        
        # 전역 변수 정리
        for obj_name in ['model_mal', 'label_encoder_mal', 'xgboost_model']:
            if obj_name in globals():
                try:
                    del globals()[obj_name]
                except:
                    pass
        
        gc.collect()
        print("메모리 정리 완료")

def main():
    """메인 실행 함수 (안정성 강화)"""
    print("=== Python 패키지 보안 분석 도구 (Final Unified) ===\n")
    
    analyzer = FinalUnifiedAnalyzer()
    successful_steps = []
    
    try:
        # 0. 초기 환경 확인 및 설정
        print("0️⃣ 초기 환경 설정 및 확인...")
        try:
            # TensorFlow 초기화 확인
            import tensorflow as tf
            print(f"[환경 확인] TensorFlow 버전: {tf.__version__}")
            if tf.config.list_physical_devices('GPU'):
                print("[환경 확인] GPU 사용 가능")
            else:
                print("[환경 확인] CPU 모드로 실행")
        except Exception as env_error:
            print(f"[환경 경고] TensorFlow 설정 이슈: {env_error}")
        
        # 1. ZIP 파일 해제 및 소스코드 추출
        print("\n1️⃣ ZIP 파일 해제 및 소스코드 추출...")
        try:
            source_data = analyzer.extract_zip_and_process_source()
            if source_data is None:
                print("❌ 소스코드 추출 실패 - ZIP 파일 또는 소스 경로 확인 필요")
                return
            successful_steps.append("소스코드 추출")
            print(f"✅ 소스코드 추출 성공: {len(source_data)}개 패키지")
        except Exception as e:
            print(f"❌ 소스코드 추출 중 오류: {e}")
            return
        
        # 2. 메타데이터 추출 및 파싱
        print("\n2️⃣ 메타데이터 추출 및 파싱...")
        try:
            meta_data = analyzer.extract_and_parse_metadata()
            if not meta_data:
                print("❌ 메타데이터 추출 실패 - metadata 폴더 확인 필요")
                return
            successful_steps.append("메타데이터 추출")
            print(f"✅ 메타데이터 추출 성공: {len(meta_data)}개 패키지")
        except Exception as e:
            print(f"❌ 메타데이터 추출 중 오류: {e}")
            return
        
        # 3. 메타데이터 전처리
        print("\n3️⃣ 메타데이터 전처리...")
        try:
            df = analyzer.preprocess_metadata()
            if df is None:
                print("❌ 메타데이터 전처리 실패")
                return
            successful_steps.append("메타데이터 전처리")
            print(f"✅ 메타데이터 전처리 성공: {len(df)}개 패키지")
        except Exception as e:
            print(f"❌ 메타데이터 전처리 중 오류: {e}")
            return
        
        # 4. LSTM 모델 로드 (재시도 메커니즘)
        print("\n4️⃣ LSTM 모델 로드...")
        lstm_load_success = False
        for attempt in range(3):
            try:
                print(f"[시도 {attempt + 1}/3] 모델 로드 중...")
                if analyzer.load_lstm_models():
                    lstm_load_success = True
                    successful_steps.append("LSTM 모델 로드")
                    print("✅ LSTM 모델 로드 성공")
                    break
                else:
                    print(f"[시도 {attempt + 1}/3] 모델 로드 실패, 재시도...")
                    time.sleep(1)
            except Exception as e:
                print(f"[시도 {attempt + 1}/3] 모델 로드 오류: {e}")
                if attempt < 2:
                    print("재시도 중...")
                    time.sleep(2)
                    
        if not lstm_load_success:
            print("❌ LSTM 모델 로드 실패 - model_mal.pkl 및 label_encoder_mal.pkl 파일 확인")
            return
        
        # 5. LSTM 코드 분석
        print("\n5️⃣ LSTM 코드 분석...")
        try:
            lstm_results = analyzer.analyze_lstm_codes()
            if lstm_results is None:
                print("❌ LSTM 분석 실패 - 소스코드 데이터 확인 필요")
                return
            successful_steps.append("LSTM 분석")
            print("✅ LSTM 분석 성공")
        except Exception as e:
            print(f"❌ LSTM 분석 중 오류: {e}")
            return
        
        # 6. LSTM 결과 통합
        print("\n6️⃣ LSTM 결과 통합...")
        try:
            if not analyzer.integrate_lstm_results():
                print("❌ 결과 통합 실패")
                return
            successful_steps.append("LSTM 결과 통합")
            print("✅ LSTM 결과 통합 성공")
        except Exception as e:
            print(f"❌ LSTM 결과 통합 중 오류: {e}")
            return
        
        # 7. XGBoost 모델 로드
        print("\n7️⃣ XGBoost 모델 로드...")
        try:
            if not analyzer.load_xgboost_model():
                print("❌ XGBoost 모델 로드 실패")
                return
            successful_steps.append("XGBoost 모델 로드")
            print("✅ XGBoost 모델 로드 성공")
        except Exception as e:
            print(f"❌ XGBoost 모델 로드 중 오류: {e}")
            return
        
        # 8. 최종 악성 예측
        print("\n8️⃣ 최종 악성 패키지 예측...")
        try:
            if not analyzer.predict_malicious():
                print("❌ 예측 실패")
                return
            successful_steps.append("악성 예측")
            print("✅ 악성 예측 성공")
        except Exception as e:
            print(f"❌ 예측 중 오류: {e}")
            return
        
        # 9. 최종 리포트 생성
        print("\n9️⃣ 최종 리포트 생성...")
        try:
            if not analyzer.generate_final_report():
                print("❌ 리포트 생성 실패")
                return
            successful_steps.append("리포트 생성")
            print("✅ 리포트 생성 성공")
        except Exception as e:
            print(f"❌ 리포트 생성 중 오류: {e}")
            return
        
        # 10. 통합 CSV 파일 생성
        print("\n🔟 통합 분석 결과 CSV 생성...")
        try:
            comprehensive_csv = analyzer.save_comprehensive_results()
            if not comprehensive_csv:
                print("❌ 통합 CSV 생성 실패")
                return
            successful_steps.append("통합 CSV 생성")
            print("✅ 통합 CSV 생성 성공")
        except Exception as e:
            print(f"❌ 통합 CSV 생성 중 오류: {e}")
            return
        
        print("\n" + "="*60)
        print("🎉 모든 분석이 완료되었습니다!")
        print("="*60)
        print(f"\n✅ 성공한 단계들: {', '.join(successful_steps)}")
        print("\n📁 생성된 파일들 (./result 폴더):")
        print("   ├── merged_sourceCode.csv: 병합된 소스코드")
        print("   ├── pypi_typo_analysis5.csv: 통합 분석 데이터")
        print("   ├── package_vulnerability_analysis.csv: LSTM 분석 결과")
        print("   ├── comprehensive_analysis_results.csv: 모든 결과 통합 CSV")
        print("   └── pypi_malicious_reason_report.txt: 최종 판단 리포트")
        print("="*60)
        
    except KeyboardInterrupt:
        print(f"\n❌ 사용자에 의해 중단되었습니다.")
        if successful_steps:
            print(f"✅ 중단 전까지 완료된 단계: {', '.join(successful_steps)}")
    except Exception as e:
        print(f"\n❌ 예기치 못한 오류가 발생했습니다: {e}")
        if successful_steps:
            print(f"✅ 오류 발생 전까지 완료된 단계: {', '.join(successful_steps)}")
        print("\n🔍 상세 오류 정보:")
        import traceback
        traceback.print_exc()
    finally:
        # 최종 메모리 정리
        print("\n🔧 시스템 정리 중...")
        try:
            analyzer.cleanup()
            print("✅ 메모리 정리 완료")
        except Exception as cleanup_error:
            print(f"⚠️ 정리 중 경고: {cleanup_error}")
        print("👋 프로그램을 종료합니다.")

if __name__ == "__main__":
    main()


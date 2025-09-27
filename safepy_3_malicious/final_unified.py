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

# 경고 메시지 숨기기
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # TensorFlow 경고 메시지 숨기기
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'  # oneDNN 최적화 비활성화
import warnings
warnings.filterwarnings('ignore')  # 모든 경고 메시지 숨기기

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
        
    def remove_comments(self, code):
        """소스 코드에서 주석 제거"""
        # 여러 줄 주석 제거
        code = re.sub(r"'''(.*?)'''", '', code, flags=re.DOTALL)
        code = re.sub(r'"""(.*?)"""', '', code, flags=re.DOTALL)
        # 한 줄 주석 제거
        code = re.sub(r'#.*', '', code)
        return code.strip()

    def extract_zip_and_process_source(self):
        """ZIP 파일 해제 및 소스코드 처리"""
        print("1️⃣ ZIP 파일 해제 및 소스코드 추출...")
        
        zip_file_path = 'python-packages-1757531529324.zip'
        extract_path = './extracted_files'
        
        # ZIP 파일 해제
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
        
        source_path = os.path.join(extract_path, 'source')
        
        # 소스코드 처리 및 CSV 저장
        source_data = self.process_directory(source_path)
        self.save_to_csv(source_data, 'merged_sourceCode.csv')
        
        print(f"✅ CSV 저장 완료: {len(source_data)}개 디렉터리 처리됨")

    def process_directory(self, root_path):
        """디렉터리 내 Python 파일들을 재귀적으로 처리"""
        data = []
        
        for dir_name in os.listdir(root_path):
            dir_path = os.path.join(root_path, dir_name)
            if os.path.isdir(dir_path):
                merged_code = ""
                
                # 모든 .py 파일을 찾아서 병합
                for root, dirs, files in os.walk(dir_path):
                    for file in files:
                        if file.endswith('.py'):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    content = f.read()
                                    # 주석 제거 후 병합
                                    merged_code += self.remove_comments(content) + "\n"
                            except Exception as e:
                                print(f"파일 읽기 오류 {file_path}: {e}")
                                continue
                
                if merged_code.strip():
                    data.append([dir_name, merged_code.strip()])
        
        return data

    def save_to_csv(self, data, output_file='merged_sourceCode.csv'):
        """데이터를 CSV로 저장"""
        os.makedirs(self.result_dir, exist_ok=True)
        output_path = os.path.join(self.result_dir, output_file)
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            if output_file == 'merged_sourceCode.csv':
                writer.writerow(['package', 'code'])  # 헤더 변경
                for row in data:
                    writer.writerow([row[0], row[1]])  # Directory -> package로 매핑
            else:
                writer.writerow(['Directory', 'MergedCodeWithoutComments'])
                writer.writerows(data)

    def extract_and_parse_metadata(self):
        """메타데이터 추출 및 파싱"""
        print("2️⃣ 메타데이터 추출 및 파싱...")
        
        extract_path = './extracted_files'
        metadata_path = os.path.join(extract_path, 'metadata')
        
        self.meta_datas = []
        
        for filename in os.listdir(metadata_path):
            if filename.endswith('.txt'):
                filepath = os.path.join(metadata_path, filename)
                metadata = self.parse_metadata_file(filepath)
                if metadata:
                    self.meta_datas.append(metadata)
        
        print(f"✅ 메타데이터 파싱 완료: {len(self.meta_datas)}개")

    def parse_metadata_file(self, filepath):
        """개별 메타데이터 파일 파싱"""
        metadata = {}
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 패키지명 추출 (파일명에서)
            package_name = os.path.basename(filepath).replace('.txt', '')
            metadata['name'] = package_name
            
            # 기본 필드들 추출
            fields = ['summary', 'version', 'author', 'author-email', 'maintainer',
                     'maintainer-email', 'license', 'platform', 'classifier',
                     'requires-dist', 'project-url', 'description']
            
            for field in fields:
                pattern = rf'^{re.escape(field)}:\s*(.+)$'
                matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
                if matches:
                    if field in ['classifier', 'requires-dist', 'project-url']:
                        metadata[field] = matches  # 리스트로 저장
                    else:
                        metadata[field] = matches[0].strip()
                else:
                    metadata[field] = None
            
            return metadata
            
        except Exception as e:
            print(f"메타데이터 파싱 오류 {filepath}: {e}")
            return None

    def preprocess_metadata(self):
        """메타데이터 전처리"""
        print("3️⃣ 메타데이터 전처리...")
        
        if not self.meta_datas:
            print("❌ 메타데이터가 없습니다.")
            return
        
        # DataFrame 생성
        self.df = pd.DataFrame(self.meta_datas)
        
        # 다운로드 수 조회
        self.df = self.get_download_counts(self.df)
        
        # 추가 피처 생성
        self.df = self.engineer_features(self.df)
        
        print(f"✅ 메타데이터 전처리 완료: {len(self.df)}개 패키지")

    def get_download_counts(self, df):
        """BigQuery를 통한 다운로드 수 조회"""
        try:
            # Google Cloud 인증 설정
            credentials = service_account.Credentials.from_service_account_file(
                'plated-mantis-471407-m4-b14f1b3e761d.json'
            )
            client = bigquery.Client(credentials=credentials, project=credentials.project_id)
            
            download_counts = []
            
            for _, row in df.iterrows():
                package_name = row['name']
                
                query = f"""
                SELECT file.project, COUNT(*) as download_count
                FROM `bigquery-public-data.pypi.file_downloads`
                WHERE file.project = '{package_name}'
                  AND DATE(timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY)
                GROUP BY file.project
                """
                
                try:
                    query_job = client.query(query)
                    results = query_job.result()
                    
                    count = 0
                    for result in results:
                        count = result.download_count
                        break
                    
                    download_counts.append(count)
                    
                except Exception as e:
                    print(f"다운로드 수 조회 실패 {package_name}: {e}")
                    download_counts.append(0)
            
            df['download'] = download_counts
            
        except Exception as e:
            print(f"BigQuery 설정 오류: {e}")
            df['download'] = 0
        
        return df

    def engineer_features(self, df):
        """피처 엔지니어링"""
        
        # 텍스트 길이 피처
        df['summary_length'] = df['summary'].fillna('').astype(str).apply(len)
        df['version_parts'] = df['version'].fillna('').astype(str).apply(lambda x: len(x.split('.')))
        
        # 이메일 도메인 추출
        def extract_domain(email):
            if pd.isna(email) or '@' not in str(email):
                return 'unknown'
            return str(email).split('@')[-1]
        
        df['author_domain'] = df['author-email'].apply(extract_domain)
        
        # 레벤슈타인 거리 계산 (패키지명 유사도)
        popular_packages = ['requests', 'numpy', 'pandas', 'flask', 'django', 'tensorflow']
        
        def min_levenshtein_distance(name, popular_list):
            if pd.isna(name):
                return 100
            min_dist = float('inf')
            for popular in popular_list:
                dist = levenshtein_distance(str(name).lower(), popular.lower())
                min_dist = min(min_dist, dist)
            return min_dist
        
        df['min_levenshtein_distance'] = df['name'].apply(
            lambda x: min_levenshtein_distance(x, popular_packages)
        )
        
        return df

    # LSTM 분석 관련 메서드들
    def detect_encoding(self, file_path):
        """파일 인코딩 감지"""
        detected_encodings = []
        
        # chardet을 이용한 인코딩 감지
        if HAS_CHARDET:
            try:
                with open(file_path, 'rb') as f:
                    sample = f.read(10000)
                    result = chardet.detect(sample)
                    if result and result['encoding'] and result['confidence'] > 0.7:
                        detected_encodings.append(result['encoding'])
                        print(f"감지된 인코딩: {result['encoding']} (신뢰도: {result['confidence']:.2f})")
            except Exception as e:
                print(f"인코딩 감지 오류: {e}")
        
        # 기본 인코딩 리스트 (Windows 환경 우선)
        default_encodings = ['utf-8', 'cp949', 'euc-kr', 'utf-8-sig', 'latin-1', 'iso-8859-1', 'utf-16']
        
        # 중복 제거하면서 순서 유지
        all_encodings = detected_encodings.copy()
        for enc in default_encodings:
            if enc not in all_encodings:
                all_encodings.append(enc)
        
        return all_encodings

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
            import dill
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
        """LSTM을 이용한 소스코드 분석"""
        print("5️⃣ LSTM 코드 분석...")
        
        csv_path = os.path.join(self.result_dir, source_csv)
        
        if not os.path.exists(csv_path):
            print(f"❌ CSV 파일이 없습니다: {csv_path}")
            return None
        
        # CSV 파일 읽기
        df = self.read_csv_data(csv_path)
        if df is None:
            print("❌ LSTM 분석 실패")
            return None
        
        print(f"\n=== LSTM 분석 시작: {len(df)}개 패키지 ===")
        
        results = []
        start_time = time.time()
        
        for idx, row in df.iterrows():
            package_name = row['package']
            source_code = row['code']
            
            print(f"LSTM 분석 중 ({idx + 1}/{len(df)}): {package_name}")
            
            # 개별 코드 분석
            result = self.analyze_single_code(source_code, package_name)
            result['package_name'] = package_name
            results.append(result)
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        print(f"\n=== LSTM 분석 완료 ===")
        print(f"총 소요 시간: {elapsed_time:.2f}초")
        print(f"패키지당 평균 시간: {elapsed_time/len(df):.2f}초")
        
        # 결과 DataFrame 생성
        results_df = pd.DataFrame(results)
        
        # 결과 저장
        output_path = os.path.join(self.result_dir, 'package_vulnerability_analysis.csv')
        results_df.to_csv(output_path, index=False)
        print(f"LSTM 분석 결과 저장: {output_path}")
        
        self.lstm_results = results_df
        return results_df

    def merge_lstm_results(self):
        """LSTM 결과를 메인 데이터와 통합"""
        print("6️⃣ LSTM 결과 통합...")
        
        if self.lstm_results is None or self.df is None:
            print("❌ 통합할 데이터가 없습니다.")
            return
        
        # 패키지명 기준으로 병합
        self.df = self.df.merge(
            self.lstm_results, 
            left_on='name', 
            right_on='package_name', 
            how='left'
        )
        
        # 불필요한 컬럼 제거
        if 'package_name' in self.df.columns:
            self.df = self.df.drop('package_name', axis=1)
        
        # 결측값 처리
        lstm_columns = ['vulnerability_status', 'cwe_label', 'confidence']
        for col in lstm_columns:
            if col in self.df.columns:
                self.df[col] = self.df[col].fillna('Unknown')
        
        # 통합 데이터 저장
        output_path = os.path.join(self.result_dir, 'pypi_typo_analysis5.csv')
        self.df.to_csv(output_path, index=False)
        print(f"통합된 분석 데이터 저장: {output_path}")

    def load_xgboost_model(self):
        """XGBoost 모델 로드"""
        print("7️⃣ XGBoost 모델 로드...")
        
        global xgboost_model
        
        try:
            model_path = os.path.join(self.current_dir, 'xgboost_model.pkl')
            with open(model_path, 'rb') as f:
                xgboost_model = pickle.load(f)
            print("XGBoost 모델 로드 성공")
            return True
        except Exception as e:
            print(f"XGBoost 모델 로드 실패: {e}")
            return False

    def predict_malicious_packages(self):
        """최종 악성 패키지 예측"""
        print("8️⃣ 최종 악성 패키지 예측...")
        
        if xgboost_model is None or self.df is None:
            print("❌ 모델 또는 데이터가 없습니다.")
            return
        
        try:
            # 예측에 필요한 피처 준비
            feature_columns = [
                'download', 'summary_length', 'version_parts', 
                'min_levenshtein_distance', 'confidence'
            ]
            
            # 결측값 처리
            prediction_df = self.df.copy()
            for col in feature_columns:
                if col in prediction_df.columns:
                    prediction_df[col] = pd.to_numeric(prediction_df[col], errors='coerce').fillna(0)
                else:
                    prediction_df[col] = 0
            
            X = prediction_df[feature_columns]
            
            # 예측 수행
            predictions = xgboost_model.predict(X)
            
            # 결과 저장
            self.df['xgboost_prediction'] = predictions
            
            # 예측 결과 요약
            result_summary = pd.DataFrame({
                'name': self.df['name'],
                'is_malicious': predictions
            })
            
            print("악성 패키지 예측 완료")
            print(result_summary)
            
        except Exception as e:
            print(f"예측 중 오류 발생: {e}")
            # 기본값으로 설정
            self.df['xgboost_prediction'] = 0

    def generate_final_report(self):
        """최종 분석 리포트 생성"""
        print("9️⃣ 최종 리포트 생성...")
        
        if self.df is None:
            print("❌ 데이터가 없습니다.")
            return
        
        report_path = os.path.join(self.result_dir, 'pypi_malicious_reason_report.txt')
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("=== Python 패키지 보안 분석 리포트 ===\n\n")
                f.write(f"분석 일시: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"총 분석 패키지 수: {len(self.df)}\n\n")
                
                # 악성 패키지 예측 결과
                if 'xgboost_prediction' in self.df.columns:
                    malicious_count = sum(self.df['xgboost_prediction'] == 1)
                    f.write(f"악성 패키지 예측: {malicious_count}개\n")
                    f.write(f"정상 패키지 예측: {len(self.df) - malicious_count}개\n\n")
                
                # 개별 패키지 분석 결과
                f.write("=== 개별 패키지 분석 결과 ===\n\n")
                
                for _, row in self.df.iterrows():
                    f.write(f"📦 패키지명: {row['name']}\n")
                    f.write(f"   버전: {row.get('version', 'Unknown')}\n")
                    f.write(f"   작성자: {row.get('author', 'Unknown')}\n")
                    f.write(f"   다운로드 수: {row.get('download', 0)}\n")
                    
                    if 'xgboost_prediction' in row:
                        prediction = "악성" if row['xgboost_prediction'] == 1 else "정상"
                        f.write(f"   최종 판단: {prediction}\n")
                    
                    if 'vulnerability_status' in row:
                        f.write(f"   LSTM 취약점 분석: {row['vulnerability_status']}\n")
                        f.write(f"   CWE 분류: {row.get('cwe_label', 'Unknown')}\n")
                        f.write(f"   신뢰도: {row.get('confidence', 0):.3f}\n")
                    
                    f.write("-" * 50 + "\n")
            
            print(f"📄 최종 분석 리포트 저장: {report_path}")
            
        except Exception as e:
            print(f"리포트 생성 오류: {e}")

    def save_comprehensive_results(self):
        """종합 분석 결과 CSV 저장"""
        print("🔟 통합 분석 결과 CSV 생성...")
        
        if self.df is None:
            print("❌ 저장할 데이터가 없습니다.")
            return
        
        try:
            # 컬럼명 정리
            columns_mapping = {
                'vulnerability_status': 'lstm_vulnerability_status',
                'cwe_label': 'lstm_cwe_label',
                'confidence': 'lstm_confidence'
            }
            
            result_df = self.df.rename(columns=columns_mapping)
            
            # 최종 결과 저장
            output_path = os.path.join(self.result_dir, 'comprehensive_analysis_results.csv')
            result_df.to_csv(output_path, index=False)
            
            # 통계 정보 출력
            print(f"📊 통합 분석 결과 CSV 저장: {output_path}")
            print(f"   - 총 패키지 수: {len(result_df)}")
            print(f"   - 총 컬럼 수: {len(result_df.columns)}")
            
            if 'xgboost_prediction' in result_df.columns:
                malicious_count = sum(result_df['xgboost_prediction'] == 1)
                print(f"   - XGBoost 예측 악성: {malicious_count}개")
                print(f"   - XGBoost 예측 정상: {len(result_df) - malicious_count}개")
            
            if 'lstm_vulnerability_status' in result_df.columns:
                vulnerable_count = sum(result_df['lstm_vulnerability_status'] == 'Vulnerable')
                print(f"   - LSTM 취약점 발견: {vulnerable_count}개")
            
            # 주요 컬럼 목록 출력
            important_cols = ['name', 'xgboost_prediction', 'lstm_vulnerability_status', 
                            'lstm_cwe_label', 'lstm_confidence', 'summary', 'author', 
                            'author-email', 'version', 'download']
            
            available_cols = [col for col in important_cols if col in result_df.columns]
            print("   - 주요 컬럼들:")
            for i, col in enumerate(available_cols[:10], 1):
                print(f"     {i}. {col}")
            
            if len(available_cols) > 10:
                print(f"     ... 외 {len(result_df.columns) - 10}개 컬럼")
            
        except Exception as e:
            print(f"결과 저장 오류: {e}")

    def cleanup_memory(self):
        """메모리 정리"""
        print("🔧 메모리 정리...")
        
        global model_mal, label_encoder_mal, xgboost_model
        
        # TensorFlow 세션 정리
        try:
            if K is not None:
                K.clear_session()
        except Exception:
            pass
        
        # 모델 객체 정리
        for obj_name in ['model_mal', 'label_encoder_mal', 'xgboost_model']:
            try:
                globals()[obj_name] = None
            except Exception:
                pass
        
        # 가비지 컬렉션
        gc.collect()
        
        print("메모리 정리 완료")

    def run_full_analysis(self):
        """전체 분석 파이프라인 실행"""
        print("=== Python 패키지 보안 분석 도구 (Final Unified) ===\n")
        
        try:
            # 1. ZIP 파일 해제 및 소스코드 추출
            self.extract_zip_and_process_source()
            
            # 2. 메타데이터 파싱
            self.extract_and_parse_metadata()
            
            # 3. 메타데이터 전처리
            self.preprocess_metadata()
            
            # 4. LSTM 모델 로드
            print("4️⃣ LSTM 모델 로드...")
            if not self.load_lstm_models():
                print("❌ LSTM 모델 로드 실패")
                return
            
            # 5. LSTM 코드 분석
            self.analyze_lstm_codes()
            
            # 6. 결과 통합
            self.merge_lstm_results()
            
            # 7. XGBoost 모델 로드
            if not self.load_xgboost_model():
                return
            
            # 8. 최종 예측
            self.predict_malicious_packages()
            
            # 9. 리포트 생성
            self.generate_final_report()
            
            # 10. 종합 결과 저장
            self.save_comprehensive_results()
            
            print("\n✅ 모든 분석이 완료되었습니다!")
            print("\n생성된 파일들 (./result 폴더):")
            print("- result/merged_sourceCode.csv: 병합된 소스코드")
            print("- result/pypi_typo_analysis5.csv: 통합 분석 데이터") 
            print("- result/package_vulnerability_analysis.csv: LSTM 분석 결과")
            print("- result/comprehensive_analysis_results.csv: 모든 결과 통합 CSV")
            print("- result/pypi_malicious_reason_report.txt: 최종 판단 리포트")
            
        except Exception as e:
            print(f"❌ 분석 중 오류 발생: {e}")
        finally:
            # 메모리 정리
            self.cleanup_memory()

def main():
    """메인 실행 함수"""
    analyzer = FinalUnifiedAnalyzer()
    analyzer.run_full_analysis()

if __name__ == "__main__":
    main()
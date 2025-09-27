"""
LSTM 기반 Python 코드 취약점 분석 도구 (CSV 버전)

이 스크립트는 [package, code] 컬럼을 가진 CSV 파일을 입력으로 받아
각 패키지의 Python 코드를 LSTM 모델로 분석하여
[package, vulnerability_status, cwe_label] 형태의 결과 CSV 파일을 생성합니다.

사용법:
1. 입력 CSV 파일 준비:
   - 'package': 패키지 이름
   - 'code': 분석할 Python 소스 코드
   
2. 입력 파일 위치 설정:
   - 방법 1: 'input_data.csv' 파일을 현재 스크립트 디렉토리에 저장
   - 방법 2: 스크립트 내 csv_input_file 변수를 원하는 파일 경로로 수정
   
3. 스크립트 실행:
   python "LSTM copy.py"
   
4. 결과 확인:
   - result/package_vulnerability_analysis.csv: CSV 형식 결과
   - result/package_vulnerability_analysis.json: JSON 형식 결과

출력 형식:
- package: 패키지 이름
- vulnerability_status: 'Vulnerable' 또는 'Not Vulnerable'
- cwe_label: CWE 분류 라벨 (취약점이 없는 경우 'Benign')

필요한 모델 파일:
- model/model_mal.pkl: 학습된 LSTM 모델
- model/label_encoder_mal.pkl: 라벨 인코더
- w2v/: Word2Vec 모델 파일들
"""

import pickle
import os
import numpy as np
import pandas as pd
import zipfile
import glob
import gc
try:
    import chardet
    HAS_CHARDET = True
except ImportError:
    HAS_CHARDET = False
from tensorflow.keras import backend as K
from preprocess import tokenize_python, embed_sequences, w2v_model

# Get the current directory (where this script is located)
current_dir = os.path.dirname(os.path.abspath(__file__))

# Define the directory where models are saved
model_save_dir = os.path.join(current_dir, 'model')

# Define the source directory
source_dir = os.path.join(current_dir, 'source')

# Define the w2v directory
w2v_dir = os.path.join(current_dir, 'w2v')

def detect_encoding(file_path):
    """Detect file encoding using chardet if available, otherwise return common encodings"""
    if HAS_CHARDET:
        try:
            with open(file_path, 'rb') as f:
                # Read a sample of the file for detection
                sample = f.read(10000)  # Read first 10KB
                result = chardet.detect(sample)
                if result['confidence'] > 0.7:  # If confidence is high enough
                    return [result['encoding']]
        except Exception as e:
            print(f"Error detecting encoding with chardet: {e}")
    
    # Default encodings to try (Korean system common encodings first)
    return ['cp949', 'euc-kr', 'utf-8', 'utf-16', 'latin-1', 'iso-8859-1']

def read_csv_data(csv_file_path):
    """Read CSV file with [package, code] columns"""
    print(f"Attempting to read CSV file: {csv_file_path}")
    
    # Get encodings to try
    encodings = detect_encoding(csv_file_path)
    
    for encoding in encodings:
        try:
            print(f"Trying to read CSV with encoding: {encoding}")
            df = pd.read_csv(csv_file_path, encoding=encoding)
            
            # Check if required columns exist
            if 'package' not in df.columns or 'code' not in df.columns:
                print(f"Error: CSV file must contain 'package' and 'code' columns")
                print(f"Found columns: {list(df.columns)}")
                return None
                
            print(f"Successfully loaded CSV file: {csv_file_path} with encoding: {encoding}")
            print(f"Number of rows: {len(df)}")
            print(f"Columns: {list(df.columns)}")
            
            return df
            
        except UnicodeDecodeError as e:
            print(f"Failed with encoding {encoding}: UnicodeDecodeError")
            continue
        except Exception as e:
            print(f"Error reading CSV file {csv_file_path} with encoding {encoding}: {e}")
            continue
    
    print(f"Failed to read CSV file with all attempted encodings: {encodings}")
    return None

def extract_zip_files():
    """Extract all zip files in the source directory"""
    extracted_files = []
    
    # Find all zip files in source directory
    zip_files = glob.glob(os.path.join(source_dir, '*.zip'))
    
    for zip_file in zip_files:
        try:
            # Create extraction directory
            extract_dir = os.path.join(source_dir, os.path.splitext(os.path.basename(zip_file))[0])
            os.makedirs(extract_dir, exist_ok=True)
            
            # Extract zip file
            with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            print(f"Extracted {zip_file} to {extract_dir}")
            extracted_files.append(extract_dir)
            
        except Exception as e:
            print(f"Error extracting {zip_file}: {e}")
    
    return extracted_files

def find_python_files(directory):
    """Find all Python files in a directory recursively"""
    python_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))
    return python_files

def read_python_file(file_path):
    """Read Python file and return its content"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

# Load the saved model and label encoder (mal-only)
model_mal = None
label_encoder_mal = None

try:
    with open(os.path.join(model_save_dir, 'model_mal.pkl'), 'rb') as f:
        model_mal = pickle.load(f)
    print("model_mal loaded successfully.")
except FileNotFoundError:
    print("Error: model_mal.pkl not found.")

try:
    with open(os.path.join(model_save_dir, 'label_encoder_mal.pkl'), 'rb') as f:
        label_encoder_mal = pickle.load(f)
    print("label_encoder_mal loaded successfully.")
except FileNotFoundError:
    print("Error: label_encoder_mal.pkl not found.")


def analyze_python_code(source_code, file_path):
    """Analyze a single Python code file for vulnerabilities"""
    print(f"\n--- Analyzing: {file_path} ---")
    print("Source Code snippet:")
    print(source_code[:500] + "..." if len(source_code) > 500 else source_code)

    # Preprocess the source code: tokenize, embed, and pad
    tokenized_code = tokenize_python(source_code)

    if w2v_model: # Ensure Word2Vec model is loaded for embedding
        embedded_code = embed_sequences([tokenized_code], w2v_model)
        if embedded_code and len(embedded_code) > 0 and embedded_code[0].size > 0:
            # Pad the embedded sequence
            max_sequence_length = 100 # Use the same max length as training
            embedding_dim = w2v_model.vector_size
            padded_code = np.zeros((max_sequence_length, embedding_dim))

            embedded_sequence = embedded_code[0]
            if embedded_sequence.shape[0] > 0:
                padding_length = max_sequence_length - embedded_sequence.shape[0]
                if padding_length > 0:
                    padding = np.zeros((padding_length, embedding_dim))
                    padded_code = np.concatenate((embedded_sequence, padding), axis=0)
                else:
                    padded_code = embedded_sequence[:max_sequence_length]

            # Reshape for prediction (add batch dimension)
            padded_code = np.expand_dims(padded_code, axis=0)

            # model_mal 단일 모델로 예측 (이진/다중분류 모두 대응)
            prediction = model_mal.predict(padded_code)
            if prediction.ndim == 2 and prediction.shape[1] == 1:
                # Binary sigmoid
                predicted_index = int((prediction > 0.5).astype(int)[0][0])
            else:
                # Multiclass softmax
                predicted_index = int(np.argmax(prediction, axis=1)[0])

            decoded_label = label_encoder_mal.inverse_transform([predicted_index])[0]

            benign_aliases = {"Benign", "benign", "Not Vulnerable", "Normal", "Safe", "0", 0}
            is_benign = decoded_label in benign_aliases

            print(f"\nPredicted Label: {decoded_label}")
            print(f"Predicted Vulnerability Status: {'Vulnerable' if not is_benign else 'Not Vulnerable'}")

        else:
            print("Error: Could not embed the source code.")
    else:
        print("Error: Word2Vec model not loaded. Cannot embed sequences.")

def analyze_csv_data(csv_file_path):
    """CSV 파일의 각 행을 분석하고 결과를 DataFrame으로 반환하는 함수"""
    import time
    
    # CSV 파일 읽기
    df = read_csv_data(csv_file_path)
    if df is None:
        return None
    
    # 분석 시작 시간 기록
    start_time = time.time()
    results = []
    
    # 각 행에 대해 분석 수행
    for index, row in df.iterrows():
        package_name = row['package']
        source_code = row['code']
        
        print(f"\n--- Analyzing package {index + 1}/{len(df)}: {package_name} ---")
        
        # 소스 코드가 비어있거나 None인 경우 처리
        if pd.isna(source_code) or source_code == '' or str(source_code).strip() == '':
            print(f"Warning: Empty code for package {package_name}")
            results.append({
                'package': package_name,
                'vulnerability_status': 'Error',
                'cwe_label': 'Empty Code'
            })
            continue
        
        # 분석 수행
        analysis_result = analyze_single_code(str(source_code), package_name)
        
        if analysis_result:
            results.append({
                'package': package_name,
                'vulnerability_status': analysis_result['vulnerability_status'],
                'cwe_label': analysis_result['cwe_label']
            })
        else:
            results.append({
                'package': package_name,
                'vulnerability_status': 'Error',
                'cwe_label': 'Analysis Failed'
            })
    
    # 분석 완료 시간 기록
    end_time = time.time()
    total_time = end_time - start_time
    
    # DataFrame 생성
    results_df = pd.DataFrame(results)
    
    print(f"\n=== CSV 데이터 분석 완료: 총 {len(results)}개 패키지 ===")
    print(f"총 소요 시간: {total_time:.2f}초")
    print(f"패키지당 평균 시간: {total_time/len(results):.2f}초" if len(results) > 0 else "패키지당 평균 시간: 0초")
    print("\n분석 결과 미리보기:")
    print(results_df.head(10))
    
    return results_df

def analyze_single_code(source_code, package_name):
    """단일 코드 분석 함수 (패키지명 포함)"""
    try:
        # Preprocess the source code: tokenize, embed, and pad
        tokenized_code = tokenize_python(source_code)

        if w2v_model: # Ensure Word2Vec model is loaded for embedding
            embedded_code = embed_sequences([tokenized_code], w2v_model)
            if embedded_code and len(embedded_code) > 0 and embedded_code[0].size > 0:
                # Pad the embedded sequence
                max_sequence_length = 100 # Use the same max length as training
                embedding_dim = w2v_model.vector_size
                padded_code = np.zeros((max_sequence_length, embedding_dim))

                embedded_sequence = embedded_code[0]
                if embedded_sequence.shape[0] > 0:
                    padding_length = max_sequence_length - embedded_sequence.shape[0]
                    if padding_length > 0:
                        padding = np.zeros((padding_length, embedding_dim))
                        padded_code = np.concatenate((embedded_sequence, padding), axis=0)
                    else:
                        padded_code = embedded_sequence[:max_sequence_length]

                # Reshape for prediction (add batch dimension)
                padded_code = np.expand_dims(padded_code, axis=0)

                # model_mal 단일 모델로 예측 (이진/다중분류 모두 대응)
                prediction = model_mal.predict(padded_code, verbose=0)  # verbose=0으로 출력 최소화
                if prediction.ndim == 2 and prediction.shape[1] == 1:
                    # Binary sigmoid
                    predicted_index = int((prediction > 0.5).astype(int)[0][0])
                else:
                    # Multiclass softmax
                    predicted_index = int(np.argmax(prediction, axis=1)[0])

                decoded_label = label_encoder_mal.inverse_transform([predicted_index])[0]

                benign_aliases = {"Benign", "benign", "Not Vulnerable", "Normal", "Safe", "0", 0}
                is_benign = decoded_label in benign_aliases

                vulnerability_status = 'Not Vulnerable' if is_benign else 'Vulnerable'
                cwe_label = 'Benign' if is_benign else decoded_label
                
                print(f"Package: {package_name} - Status: {vulnerability_status} - CWE: {cwe_label}")

                return {
                    'vulnerability_status': vulnerability_status,
                    'cwe_label': cwe_label
                }
            else:
                print(f"Error: Could not embed the source code for package {package_name}")
                return None
        else:
            print("Error: Word2Vec model not loaded. Cannot embed sequences.")
            return None
    except Exception as e:
        print(f"Error analyzing package {package_name}: {e}")
        return None

def analyze_multiple_files():
    """여러 파일을 분석하고 결과를 DataFrame으로 반환하는 함수"""
    import time
    
    # 분석 시작 시간 기록
    start_time = time.time()
    results = []
    
    # Extract zip files from source directory
    extracted_dirs = extract_zip_files()
    
    if not extracted_dirs:
        print("No zip files found in source directory. Please place zip files containing Python code in the 'source' folder.")
        return None
    
    # Analyze all Python files in extracted directories
    for extract_dir in extracted_dirs:
        print(f"\n=== Analyzing files in: {extract_dir} ===")
        python_files = find_python_files(extract_dir)
        
        if not python_files:
            print(f"No Python files found in {extract_dir}")
            continue
            
        for py_file in python_files:
            source_code = read_python_file(py_file)
            if source_code:
                # 파일 경로에서 상대 경로만 추출
                relative_path = os.path.relpath(py_file, current_dir)
                
                # 분석 수행
                analysis_result = analyze_single_file(source_code, py_file)
                
                if analysis_result:
                    results.append({
                        'file_path': relative_path,
                        'file_name': os.path.basename(py_file),
                        'vulnerability_status': analysis_result['vulnerability_status'],
                        'cwe_label': analysis_result['cwe_label']
                    })
                else:
                    results.append({
                        'file_path': relative_path,
                        'file_name': os.path.basename(py_file),
                        'vulnerability_status': 'Error',
                        'cwe_label': 'Error'
                    })
            else:
                relative_path = os.path.relpath(py_file, current_dir)
                results.append({
                    'file_path': relative_path,
                    'file_name': os.path.basename(py_file),
                    'vulnerability_status': 'Error',
                    'cwe_label': 'Error'
                })
    
    # 분석 완료 시간 기록
    end_time = time.time()
    total_time = end_time - start_time
    
    # DataFrame 생성
    df = pd.DataFrame(results)
    
    print(f"\n=== 분석 완료: 총 {len(results)}개 파일 ===")
    print(f"총 소요 시간: {total_time:.2f}초")
    print(f"파일당 평균 시간: {total_time/len(results):.2f}초" if len(results) > 0 else "파일당 평균 시간: 0초")
    print("\n분석 결과 미리보기:")
    print(df.head(10))
    
    return df

def save_analysis_results(df, output_format='csv', output_filename='analysis_results'):
    """분석 결과를 다양한 형식으로 저장하는 함수"""
    if df is None or df.empty:
        print("저장할 데이터가 없습니다.")
        return None
    
    # result 폴더 생성
    result_dir = os.path.join(current_dir, 'result')
    os.makedirs(result_dir, exist_ok=True)
    
    if output_format.lower() == 'csv':
        # CSV 형식으로 저장
        output_file = os.path.join(result_dir, f'{output_filename}.csv')
        df.to_csv(output_file, index=False, encoding='utf-8-sig')
        print(f"CSV 파일이 {output_file}에 저장되었습니다.")
        
    elif output_format.lower() == 'json':
        # JSON 형식으로 저장
        output_file = os.path.join(result_dir, f'{output_filename}.json')
        df.to_json(output_file, orient='records', indent=2, force_ascii=False)
        print(f"JSON 파일이 {output_file}에 저장되었습니다.")
        
    elif output_format.lower() == 'excel':
        # Excel 형식으로 저장
        output_file = os.path.join(result_dir, f'{output_filename}.xlsx')
        df.to_excel(output_file, index=False, engine='openpyxl')
        print(f"Excel 파일이 {output_file}에 저장되었습니다.")
        
    else:
        print(f"지원하지 않는 형식입니다: {output_format}")
        return None
    
    return output_file

def process_csv_file(csv_input_path, csv_output_filename='package_vulnerability_analysis'):
    """CSV 파일을 처리하여 취약점 분석 결과를 저장하는 메인 함수"""
    print(f"=== CSV 파일 취약점 분석 시작 ===")
    print(f"입력 파일: {csv_input_path}")
    
    # CSV 데이터 분석
    analysis_df = analyze_csv_data(csv_input_path)
    
    if analysis_df is not None:
        # 결과 저장
        output_file = save_analysis_results(analysis_df, 'csv', csv_output_filename)
        
        # 추가 형식으로도 저장 (선택사항)
        save_analysis_results(analysis_df, 'json', csv_output_filename)
        
        # 결과 요약 출력
        print(f"\n=== 분석 완료 요약 ===")
        print(f"총 패키지 수: {len(analysis_df)}")
        
        # 취약점 상태별 통계
        status_counts = analysis_df['vulnerability_status'].value_counts()
        print("취약점 상태별 통계:")
        for status, count in status_counts.items():
            print(f"  {status}: {count}개")
            
        # CWE 라벨별 통계 (취약점만)
        vulnerable_df = analysis_df[analysis_df['vulnerability_status'] == 'Vulnerable']
        if len(vulnerable_df) > 0:
            cwe_counts = vulnerable_df['cwe_label'].value_counts()
            print(f"\nCWE 라벨별 통계 (취약점 {len(vulnerable_df)}개):")
            for cwe, count in cwe_counts.items():
                print(f"  {cwe}: {count}개")
        
        return output_file
    else:
        print("CSV 파일 분석에 실패했습니다.")
        return None

def analyze_single_file(source_code, file_path):
    """단일 파일 분석 함수"""
    try:
        # Preprocess the source code: tokenize, embed, and pad
        tokenized_code = tokenize_python(source_code)

        if w2v_model: # Ensure Word2Vec model is loaded for embedding
            embedded_code = embed_sequences([tokenized_code], w2v_model)
            if embedded_code and len(embedded_code) > 0 and embedded_code[0].size > 0:
                # Pad the embedded sequence
                max_sequence_length = 100 # Use the same max length as training
                embedding_dim = w2v_model.vector_size
                padded_code = np.zeros((max_sequence_length, embedding_dim))

                embedded_sequence = embedded_code[0]
                if embedded_sequence.shape[0] > 0:
                    padding_length = max_sequence_length - embedded_sequence.shape[0]
                    if padding_length > 0:
                        padding = np.zeros((padding_length, embedding_dim))
                        padded_code = np.concatenate((embedded_sequence, padding), axis=0)
                    else:
                        padded_code = embedded_sequence[:max_sequence_length]

                # Reshape for prediction (add batch dimension)
                padded_code = np.expand_dims(padded_code, axis=0)

                # model_mal 단일 모델로 예측 (이진/다중분류 모두 대응)
                prediction = model_mal.predict(padded_code)
                if prediction.ndim == 2 and prediction.shape[1] == 1:
                    # Binary sigmoid
                    predicted_index = int((prediction > 0.5).astype(int)[0][0])
                else:
                    # Multiclass softmax
                    predicted_index = int(np.argmax(prediction, axis=1)[0])

                decoded_label = label_encoder_mal.inverse_transform([predicted_index])[0]

                benign_aliases = {"Benign", "benign", "Not Vulnerable", "Normal", "Safe", "0", 0}
                is_benign = decoded_label in benign_aliases

                return {
                    'vulnerability_status': 'Benign' if is_benign else 'Vulnerable',
                    'cwe_label': 'Benign' if is_benign else decoded_label
                }
            else:
                return None
        else:
            return None
    except Exception as e:
        print(f"Error analyzing {file_path}: {e}")
        return None

# Ensure model and label encoder are loaded before proceeding
if model_mal and label_encoder_mal:
    print("Model and label encoder loaded successfully. Starting analysis...")
    
    # CSV 파일 경로 설정 (사용자가 수정 가능)
    # 예시: 'data.csv' 파일이 현재 디렉토리에 있다고 가정
    csv_input_file = os.path.join(current_dir, 'final_dataset.csv')
    
    # 또는 절대 경로로 지정 가능
    # csv_input_file = r"C:\path\to\your\input_file.csv"
    
    print(f"Looking for CSV input file: {csv_input_file}")
    
    # CSV 파일 존재 여부 확인
    if os.path.exists(csv_input_file):
        print(f"Found CSV file: {csv_input_file}")
        # CSV 파일 처리
        result_file = process_csv_file(csv_input_file, 'package_vulnerability_analysis')
        if result_file:
            print(f"\n=== 최종 결과 파일: {result_file} ===")
        else:
            print("CSV 파일 처리 중 오류가 발생했습니다.")
    else:
        print(f"CSV 파일을 찾을 수 없습니다: {csv_input_file}")
        print("다음 중 하나의 방법으로 CSV 파일을 제공해주세요:")
        print("1. 'input_data.csv' 파일을 현재 디렉토리에 생성")
        print("2. 스크립트에서 csv_input_file 변수를 올바른 경로로 수정")
        print("3. 또는 기존의 압축 파일 분석을 원한다면 아래 코드 활성화")
        
        # 기존 압축 파일 분석 방식도 선택 가능하도록 남겨둠
        print("\n대안: 압축 파일 분석 모드를 사용하시겠습니까? (y/n)")
        # use_zip_mode = input().strip().lower()  # 실제 사용시 주석 해제
        use_zip_mode = 'n'  # 기본값을 'n'으로 설정
        
        if use_zip_mode == 'y':
            print("압축 파일 분석 모드 실행...")
            # 1. 파일 분석 수행
            analysis_df = analyze_multiple_files()
            
            # 2. 결과 저장 (여러 형식 지원)
            if analysis_df is not None:
                # CSV 형식으로 저장
                save_analysis_results(analysis_df, 'csv', 'zip_file_analysis')
                
                # JSON 형식으로도 저장 (서버 대시보드용)
                save_analysis_results(analysis_df, 'json', 'zip_file_analysis')
        else:
            print("CSV 파일을 준비한 후 다시 실행해주세요.")

else:
    print("Error: model_mal or label_encoder_mal failed to load. Cannot perform analysis.")

# --- Graceful cleanup to avoid TensorFlow teardown warnings ---
try:
    # Clear TF/Keras session and free graph/resources
    K.clear_session()
except Exception:
    pass

# Help GC by dropping large objects
for _obj in [
    'model_mal', 'label_encoder_mal'
]:
    if _obj in globals():
        try:
            del globals()[_obj]
        except Exception:
            pass

gc.collect()

"""
LSTM 기반 취약점 탐지 파이프라인 (safepy_3)

절차:
1) source 폴더의 ZIP 해제 → 파이썬 파일 수집
2) 전처리(토큰화 → Word2Vec 임베딩 → 패딩)
3) 이진 모델(model_final)로 취약/정상 판정
4) 취약 시 다중분류(model_full)로 CWE 라벨 추정
5) CSV/JSON 결과 저장
"""

import pickle
import os
import numpy as np
import pandas as pd
import zipfile
import glob
import gc
# Keras backend import removed to avoid DLL issues
from preprocess import tokenize_python, embed_sequences, w2v_model

# Get the current directory (where this script is located)
current_dir = os.path.dirname(os.path.abspath(__file__))

# Define the directory where models are saved
model_save_dir = os.path.join(current_dir, 'model')

# Define the source directory
source_dir = os.path.join(current_dir, 'source')

# Define the w2v directory
w2v_dir = os.path.join(current_dir, 'w2v')

def extract_zip_files():
    """source 폴더 내 ZIP 파일을 모두 해제하고 추출 폴더 경로 목록을 반환.

    Returns:
    	추출된 디렉토리 경로 리스트
    """
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
    """디렉토리 하위의 모든 .py 파일 경로를 재귀적으로 수집.

    Args:
    	directory: 탐색 시작 루트

    Returns:
    	파일 경로 리스트
    """
    python_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))
    return python_files

def read_python_file(file_path):
    """파이썬 파일을 UTF-8로 읽어 내용 문자열을 반환.

    Args:
    	file_path: 파일 경로

    Returns:
    	파일 내용 문자열 또는 None
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

# Load the saved models and label encoders
model_full = None
model_final = None
label_encoder_full = None
label_encoder_final = None

try:
    with open(os.path.join(model_save_dir, 'model_full.pkl'), 'rb') as f:
        model_full = pickle.load(f)
    print("model_full loaded successfully.")
    
    # GPU 최적화: TensorFlow/Keras 모델 최적화
    import tensorflow as tf
    if tf.config.list_physical_devices('GPU'):
        print("[GPU 최적화] TensorFlow GPU 사용 가능")
        # GPU 메모리 증가 허용
        gpus = tf.config.experimental.list_physical_devices('GPU')
        if gpus:
            try:
                for gpu in gpus:
                    tf.config.experimental.set_memory_growth(gpu, True)
                print("[GPU 최적화] 동적 메모리 할당 활성화")
            except RuntimeError as e:
                print(f"[GPU 최적화] 메모리 설정 실패: {e}")
    
except FileNotFoundError:
    print("Error: model_full.pkl not found.")

try:
    # 변환된 TensorFlow 2.15.0 호환 모델 로드
    with open(os.path.join(model_save_dir, 'model_final_tf215.pkl'), 'rb') as f:
        model_final = pickle.load(f)
    print("model_final loaded successfully.")
except FileNotFoundError:
    print("Error: model_final.pkl not found.")

try:
    with open(os.path.join(model_save_dir, 'label_encoder_full.pkl'), 'rb') as f:
        label_encoder_full = pickle.load(f)
    print("label_encoder_full loaded successfully.")
except FileNotFoundError:
    print("Error: label_encoder_full.pkl not found.")

try:
    with open(os.path.join(model_save_dir, 'label_encoder_final.pkl'), 'rb') as f:
        label_encoder_final = pickle.load(f)
    print("label_encoder_final loaded successfully.")
except FileNotFoundError:
    print("Error: label_encoder_final.pkl not found.")


# 사용되지 않는 콘솔 샘플 함수(analyze_python_code)는 제거했습니다.

def analyze_multiple_files():
    """여러 파일을 분석하고 결과를 DataFrame으로 반환.
    - source/ ZIP 해제 → .py 수집 → 전처리 → 이진/다중분류

    Returns:
    	분석 결과 DataFrame 또는 None
    """
    import time
    
    # 분석 시작 시간 기록
    start_time = time.time()
    results = []
    
    # ZIP 해제
    extracted_dirs = extract_zip_files()
    
    if not extracted_dirs:
        print("No zip files found in source directory. Please place zip files containing Python code in the 'source' folder.")
        return None
    
    # 추출 폴더들 순회
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

def save_analysis_results(df, output_format='csv'):
    """분석 결과를 다양한 형식(csv/json/excel)으로 저장.

    Args:
    	df: 분석 결과 DataFrame
    	output_format: 'csv' | 'json' | 'excel'

    Returns:
    	저장된 파일 경로 또는 None
    """
    if df is None or df.empty:
        print("저장할 데이터가 없습니다.")
        return None
    
    # result 폴더 생성
    result_dir = os.path.join(current_dir, 'result')
    os.makedirs(result_dir, exist_ok=True)
    
    if output_format.lower() == 'csv':
        # CSV 형식으로 저장
        output_file = os.path.join(result_dir, 'analysis_results.csv')
        df.to_csv(output_file, index=False, encoding='utf-8-sig')
        print(f"CSV 파일이 {output_file}에 저장되었습니다.")
        
    elif output_format.lower() == 'json':
        # JSON 형식으로 저장
        output_file = os.path.join(result_dir, 'analysis_results.json')
        df.to_json(output_file, orient='records', indent=2, force_ascii=False)
        print(f"JSON 파일이 {output_file}에 저장되었습니다.")
        
    elif output_format.lower() == 'excel':
        # Excel 형식으로 저장
        output_file = os.path.join(result_dir, 'analysis_results.xlsx')
        df.to_excel(output_file, index=False, engine='openpyxl')
        print(f"Excel 파일이 {output_file}에 저장되었습니다.")
        
    else:
        print(f"지원하지 않는 형식입니다: {output_format}")
        return None
    
    return output_file

def analyze_single_file(source_code, file_path):
    """단일 파일 분석: 전처리 → 이진 판정 → 취약 시 CWE 추정.

    Args:
    	source_code: 파일 텍스트
    	file_path: 파일 경로(로그용)

    Returns:
    	{'vulnerability_status': 'Vulnerable'|'Benign', 'cwe_label': str} 또는 None
    """
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

                # 2) 이진 분류(취약/정상)
                prediction_final = model_final.predict(padded_code)
                predicted_label = (prediction_final > 0.5).astype(int)[0][0] # Binary classification threshold
                predicted_vulnerability_status = label_encoder_final.inverse_transform([predicted_label])[0]

                # 3) 취약 시 CWE 다중분류로 상세 라벨
                if predicted_vulnerability_status == 1:
                    prediction_full = model_full.predict(padded_code)
                    predicted_cwe_index = np.argmax(prediction_full, axis=1)[0]
                    predicted_cwe = label_encoder_full.inverse_transform([predicted_cwe_index])[0]
                    cwe_label = predicted_cwe
                else:
                    cwe_label = 'Benign'

                return {
                    'vulnerability_status': 'Vulnerable' if predicted_vulnerability_status == 1 else 'Benign',
                    'cwe_label': cwe_label
                }
            else:
                return None
        else:
            return None
    except Exception as e:
        print(f"Error analyzing {file_path}: {e}")
        return None

def main():
    """엔드투엔드 실행: 모델 확인 → 다중 파일 분석 → 결과 저장 → 정리."""
    if not (model_full and model_final and label_encoder_full and label_encoder_final):
        print("Error: One or more models/label encoders failed to load. Cannot perform analysis.")
        return

    print("All models loaded successfully. Starting analysis...")
    analysis_df = analyze_multiple_files()
    if analysis_df is not None:
        save_analysis_results(analysis_df, 'csv')
        save_analysis_results(analysis_df, 'json')
        # 필요 시 Excel 저장 활성화
        # save_analysis_results(analysis_df, 'excel')

    # --- 종료 정리 ---
    # K.clear_session() 제거됨 - gc.collect()로 충분
    for _obj in ['model_full', 'model_final', 'label_encoder_full', 'label_encoder_final']:
        if _obj in globals():
            try:
                del globals()[_obj]
            except Exception:
                pass
    gc.collect()


if __name__ == "__main__":
    os.makedirs(source_dir, exist_ok=True)
    main()
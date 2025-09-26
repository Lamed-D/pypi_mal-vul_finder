import pickle
import os
import numpy as np
import pandas as pd
import zipfile
import glob
import gc
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
                        'malicious_status': analysis_result['malicious_status'],
                        'malicious_probability': analysis_result['malicious_probability']
                    })
                else:
                    results.append({
                        'file_path': relative_path,
                        'file_name': os.path.basename(py_file),
                        'malicious_status': 'error',
                        'malicious_probability': 0.0
                    })
            else:
                relative_path = os.path.relpath(py_file, current_dir)
                results.append({
                    'file_path': relative_path,
                    'file_name': os.path.basename(py_file),
                    'malicious_status': 'error',
                    'malicious_probability': 0.0
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
    """분석 결과를 다양한 형식으로 저장하는 함수"""
    if df is None or df.empty:
        print("저장할 데이터가 없습니다.")
        return None
    
    # result 폴더 생성
    result_dir = os.path.join(current_dir, 'result')
    os.makedirs(result_dir, exist_ok=True)
    
    if output_format.lower() == 'csv':
        # CSV 형식으로 저장
        output_file = os.path.join(result_dir, '악성 LSTM 탐지 결과.csv')
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
                
                # 예측 확률 계산
                if prediction.ndim == 2 and prediction.shape[1] == 1:
                    # Binary sigmoid - 악성 확률
                    malicious_probability = float(prediction[0][0])
                    predicted_index = int((prediction > 0.5).astype(int)[0][0])
                else:
                    # Multiclass softmax - 악성 클래스의 확률
                    predicted_index = int(np.argmax(prediction, axis=1)[0])
                    malicious_probability = float(prediction[0][predicted_index])

                decoded_label = label_encoder_mal.inverse_transform([predicted_index])[0]

                benign_aliases = {"Benign", "benign", "Not Vulnerable", "Normal", "Safe", "0", 0}
                is_benign = decoded_label in benign_aliases

                return {
                    'malicious_status': 'malicious' if not is_benign else 'benign',
                    'malicious_probability': malicious_probability
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
    
    # 1. 파일 분석 수행
    analysis_df = analyze_multiple_files()
    
    # 2. 결과 저장 (여러 형식 지원)
    if analysis_df is not None:
        # CSV 형식으로 저장
        save_analysis_results(analysis_df, 'csv')
        
        # JSON 형식으로도 저장 (서버 대시보드용)
        save_analysis_results(analysis_df, 'json')
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
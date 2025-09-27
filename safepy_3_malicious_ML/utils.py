"""
유틸리티 함수 모듈
================

분석 도구에서 사용되는 공통 유틸리티 함수들을 정의합니다.
"""

import os
import gc
import time
import zipfile
import pandas as pd
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def setup_tensorflow_optimizations():
    """TensorFlow 성능 최적화 설정"""
    import os
    from config import TF_OPTIMIZATIONS
    
    for key, value in TF_OPTIMIZATIONS.items():
        os.environ[key] = value
    
    logger.info("TensorFlow 최적화 설정 완료")

def cleanup_memory():
    """메모리 정리"""
    gc.collect()
    logger.info("메모리 정리 완료")

def extract_zip_files(zip_path: str, extract_to: str) -> List[str]:
    """
    ZIP 파일을 추출하고 추출된 디렉토리 목록을 반환
    
    Args:
        zip_path: 추출할 ZIP 파일 경로
        extract_to: 추출할 대상 디렉토리
        
    Returns:
        추출된 디렉토리 경로 목록
    """
    extracted_dirs = []
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
            
        # 추출된 디렉토리 찾기
        for item in os.listdir(extract_to):
            item_path = os.path.join(extract_to, item)
            if os.path.isdir(item_path):
                extracted_dirs.append(item_path)
                
        logger.info(f"ZIP 파일 추출 완료: {len(extracted_dirs)}개 디렉토리")
        return extracted_dirs
        
    except Exception as e:
        logger.error(f"ZIP 파일 추출 실패: {e}")
        return []

def find_python_files(directory: str) -> List[str]:
    """
    디렉토리에서 Python 파일들을 재귀적으로 찾기
    
    Args:
        directory: 검색할 디렉토리 경로
        
    Returns:
        Python 파일 경로 목록
    """
    python_files = []
    
    try:
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
                    
        logger.info(f"Python 파일 {len(python_files)}개 발견")
        return python_files
        
    except Exception as e:
        logger.error(f"Python 파일 검색 실패: {e}")
        return []

def read_python_file(file_path: str) -> Optional[str]:
    """
    Python 파일 내용을 안전하게 읽기
    
    Args:
        file_path: 읽을 파일 경로
        
    Returns:
        파일 내용 문자열 (실패시 None)
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return content
    except UnicodeDecodeError:
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
            return content
        except Exception as e:
            logger.warning(f"파일 읽기 실패 ({file_path}): {e}")
            return None
    except Exception as e:
        logger.warning(f"파일 읽기 실패 ({file_path}): {e}")
        return None

def save_results_to_csv(data: List[Dict[str, Any]], filename: str, output_dir: str = "result"):
    """
    분석 결과를 CSV 파일로 저장
    
    Args:
        data: 저장할 데이터 리스트
        filename: 저장할 파일명
        output_dir: 출력 디렉토리
    """
    try:
        os.makedirs(output_dir, exist_ok=True)
        file_path = os.path.join(output_dir, filename)
        
        df = pd.DataFrame(data)
        df.to_csv(file_path, index=False, encoding='utf-8-sig')
        
        logger.info(f"결과 저장 완료: {file_path}")
        
    except Exception as e:
        logger.error(f"결과 저장 실패: {e}")

def save_results_to_txt(content: str, filename: str, output_dir: str = "result"):
    """
    분석 결과를 텍스트 파일로 저장
    
    Args:
        content: 저장할 내용
        filename: 저장할 파일명
        output_dir: 출력 디렉토리
    """
    try:
        os.makedirs(output_dir, exist_ok=True)
        file_path = os.path.join(output_dir, filename)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
            
        logger.info(f"텍스트 파일 저장 완료: {file_path}")
        
    except Exception as e:
        logger.error(f"텍스트 파일 저장 실패: {e}")

def format_analysis_time(start_time: float, end_time: float) -> str:
    """분석 시간을 포맷팅"""
    duration = end_time - start_time
    if duration < 60:
        return f"{duration:.2f}초"
    elif duration < 3600:
        return f"{duration/60:.2f}분"
    else:
        return f"{duration/3600:.2f}시간"

def print_progress(current: int, total: int, prefix: str = "진행률"):
    """진행률 출력"""
    percent = (current / total) * 100
    print(f"\r{prefix}: {current}/{total} ({percent:.1f}%)", end="", flush=True)
    if current == total:
        print()  # 완료시 줄바꿈

"""
Python 패키지 보안 분석 도구 - 메인 실행 파일
==========================================

이 파일은 통합된 보안 분석 파이프라인의 메인 진입점입니다.
"""

import os
import sys
import time
import logging
from pathlib import Path
from typing import List, Dict, Any

# 프로젝트 루트를 Python 경로에 추가
sys.path.insert(0, str(Path(__file__).parent))

from config import *
from utils import (
    setup_tensorflow_optimizations, 
    extract_zip_files, 
    find_python_files,
    read_python_file,
    save_results_to_csv,
    save_results_to_txt,
    format_analysis_time,
    print_progress
)
from analyzer import SecurityAnalyzer

# 로깅 설정
logging.basicConfig(level=getattr(logging, LOG_LEVEL), format=LOG_FORMAT)
logger = logging.getLogger(__name__)

class SecurityAnalysisPipeline:
    """보안 분석 파이프라인"""
    
    def __init__(self):
        """파이프라인 초기화"""
        self.analyzer = None
        self.results = []
        self.start_time = None
    
    def initialize(self):
        """파이프라인 초기화"""
        logger.info("보안 분석 파이프라인 초기화 중...")
        
        # TensorFlow 최적화 설정
        setup_tensorflow_optimizations()
        
        # 분석기 초기화
        self.analyzer = SecurityAnalyzer()
        
        logger.info("파이프라인 초기화 완료")
    
    def process_zip_file(self, zip_path: str) -> List[Dict[str, Any]]:
        """
        ZIP 파일 처리
        
        Args:
            zip_path: 처리할 ZIP 파일 경로
            
        Returns:
            분석 결과 리스트
        """
        logger.info(f"ZIP 파일 처리 시작: {zip_path}")
        
        # ZIP 파일 추출
        extracted_dirs = extract_zip_files(zip_path, str(SOURCE_DIR))
        if not extracted_dirs:
            logger.error("ZIP 파일 추출 실패")
            return []
        
        results = []
        
        for dir_path in extracted_dirs:
            logger.info(f"디렉토리 처리 중: {dir_path}")
            
            # Python 파일 찾기
            python_files = find_python_files(dir_path)
            
            for i, file_path in enumerate(python_files):
                print_progress(i + 1, len(python_files), f"파일 분석 중 ({os.path.basename(dir_path)})")
                
                # 파일 내용 읽기
                code = read_python_file(file_path)
                if not code:
                    continue
                
                # 패키지 데이터 구성
                package_data = {
                    'name': os.path.basename(dir_path),
                    'file_path': file_path,
                    'code': code,
                    'file_count': len(python_files)
                }
                
                # 분석 수행
                analysis_result = self.analyzer.analyze_package(package_data)
                if 'error' not in analysis_result:
                    results.append({
                        'package_name': package_data['name'],
                        'file_path': file_path,
                        'vulnerability_detected': analysis_result['vulnerability']['is_vulnerable'],
                        'vulnerability_confidence': analysis_result['vulnerability']['confidence'],
                        'malicious_detected': analysis_result['malicious']['is_malicious'],
                        'malicious_confidence': analysis_result['malicious']['confidence']
                    })
        
        logger.info(f"ZIP 파일 처리 완료: {len(results)}개 결과")
        return results
    
    def generate_report(self, results: List[Dict[str, Any]]) -> str:
        """
        분석 결과 리포트 생성
        
        Args:
            results: 분석 결과 리스트
            
        Returns:
            리포트 텍스트
        """
        logger.info("분석 리포트 생성 중...")
        
        total_packages = len(results)
        vulnerable_packages = sum(1 for r in results if r['vulnerability_detected'])
        malicious_packages = sum(1 for r in results if r['malicious_detected'])
        
        report = f"""
Python 패키지 보안 분석 리포트
============================

분석 일시: {time.strftime('%Y-%m-%d %H:%M:%S')}
총 분석 패키지 수: {total_packages}

취약점 분석 결과:
- 취약점이 발견된 패키지: {vulnerable_packages}개
- 취약점 발견률: {(vulnerable_packages/total_packages*100):.1f}%

악성 코드 분석 결과:
- 악성 코드가 발견된 패키지: {malicious_packages}개
- 악성 코드 발견률: {(malicious_packages/total_packages*100):.1f}%

상세 결과:
"""
        
        for result in results:
            if result['vulnerability_detected'] or result['malicious_detected']:
                report += f"""
패키지명: {result['package_name']}
파일 경로: {result['file_path']}
취약점 탐지: {'예' if result['vulnerability_detected'] else '아니오'} (신뢰도: {result['vulnerability_confidence']:.3f})
악성 코드 탐지: {'예' if result['malicious_detected'] else '아니오'} (신뢰도: {result['malicious_confidence']:.3f})
"""
        
        return report
    
    def save_results(self, results: List[Dict[str, Any]], report: str):
        """분석 결과 저장"""
        logger.info("분석 결과 저장 중...")
        
        # CSV 파일로 저장
        save_results_to_csv(results, OUTPUT_FILES['vulnerability_analysis'], str(RESULT_DIR))
        
        # 리포트 텍스트 파일로 저장
        save_results_to_txt(report, OUTPUT_FILES['malicious_report'], str(RESULT_DIR))
        
        logger.info("결과 저장 완료")
    
    def run(self, zip_path: str):
        """파이프라인 실행"""
        self.start_time = time.time()
        
        try:
            # 초기화
            self.initialize()
            
            # ZIP 파일 처리
            results = self.process_zip_file(zip_path)
            
            if not results:
                logger.warning("분석할 데이터가 없습니다.")
                return
            
            # 리포트 생성
            report = self.generate_report(results)
            
            # 결과 저장
            self.save_results(results, report)
            
            # 완료 메시지
            duration = format_analysis_time(self.start_time, time.time())
            logger.info(f"분석 완료! 소요 시간: {duration}")
            
        except Exception as e:
            logger.error(f"파이프라인 실행 중 오류 발생: {e}")
            raise
        finally:
            # 정리
            if self.analyzer:
                self.analyzer.cleanup()

def main():
    """메인 함수"""
    print("🔍 Python 패키지 보안 분석 도구")
    print("=" * 50)
    
    # ZIP 파일 경로 설정 (실제 사용시 적절한 경로로 변경)
    zip_path = str(SOURCE_DIR / "python-packages-1757595213589.zip")
    
    if not os.path.exists(zip_path):
        print(f"❌ ZIP 파일을 찾을 수 없습니다: {zip_path}")
        print("📁 source/ 디렉토리에 분석할 ZIP 파일을 넣어주세요.")
        return
    
    # 파이프라인 실행
    pipeline = SecurityAnalysisPipeline()
    pipeline.run(zip_path)

if __name__ == "__main__":
    main()

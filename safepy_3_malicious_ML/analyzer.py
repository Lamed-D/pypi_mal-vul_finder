"""
보안 분석기 모듈
===============

LSTM과 XGBoost를 사용한 Python 패키지 보안 분석을 수행합니다.
"""

import os
import pickle
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
import logging
from config import *
from utils import cleanup_memory, print_progress
from preprocess import tokenize_python, embed_sequences

logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    """Python 패키지 보안 분석기"""
    
    def __init__(self):
        """분석기 초기화"""
        self.lstm_model = None
        self.label_encoder = None
        self.xgboost_model = None
        self.w2v_model = None
        self._load_models()
    
    def _load_models(self):
        """모델들 로드"""
        try:
            # LSTM 모델 로드
            with open(LSTM_MODEL_PATH, 'rb') as f:
                self.lstm_model = pickle.load(f)
            logger.info("LSTM 모델 로드 완료")
            
            # 라벨 인코더 로드
            with open(LABEL_ENCODER_PATH, 'rb') as f:
                self.label_encoder = pickle.load(f)
            logger.info("라벨 인코더 로드 완료")
            
            # XGBoost 모델 로드
            with open(XGBOOST_MODEL_PATH, 'rb') as f:
                self.xgboost_model = pickle.load(f)
            logger.info("XGBoost 모델 로드 완료")
            
            # Word2Vec 모델 로드
            from gensim.models import Word2Vec
            self.w2v_model = Word2Vec.load(str(W2V_MODEL_PATH))
            logger.info("Word2Vec 모델 로드 완료")
            
        except Exception as e:
            logger.error(f"모델 로드 실패: {e}")
            raise
    
    def analyze_vulnerability(self, code: str) -> Dict[str, Any]:
        """
        LSTM을 사용한 취약점 분석
        
        Args:
            code: 분석할 Python 코드
            
        Returns:
            분석 결과 딕셔너리
        """
        try:
            # 코드 전처리
            tokens = tokenize_python(code)
            if not tokens:
                return {"is_vulnerable": False, "confidence": 0.0, "error": "토큰화 실패"}
            
            # 임베딩
            embedded = embed_sequences([tokens], self.w2v_model)
            if not embedded or len(embedded) == 0:
                return {"is_vulnerable": False, "confidence": 0.0, "error": "임베딩 실패"}
            
            # 패딩
            padded = self._pad_sequence(embedded[0])
            
            # 예측
            prediction = self.lstm_model.predict(padded.reshape(1, -1, EMBEDDING_DIM))
            confidence = float(prediction[0][0])
            is_vulnerable = confidence > 0.5
            
            return {
                "is_vulnerable": is_vulnerable,
                "confidence": confidence,
                "error": None
            }
            
        except Exception as e:
            logger.error(f"취약점 분석 실패: {e}")
            return {"is_vulnerable": False, "confidence": 0.0, "error": str(e)}
    
    def _pad_sequence(self, sequence: np.ndarray) -> np.ndarray:
        """시퀀스 패딩"""
        if len(sequence) >= MAX_SEQUENCE_LENGTH:
            return sequence[:MAX_SEQUENCE_LENGTH]
        else:
            padding = np.zeros((MAX_SEQUENCE_LENGTH - len(sequence), EMBEDDING_DIM))
            return np.vstack([sequence, padding])
    
    def analyze_malicious(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        XGBoost를 사용한 악성 코드 분석
        
        Args:
            features: 분석할 특성 딕셔너리
            
        Returns:
            분석 결과 딕셔너리
        """
        try:
            # 특성을 DataFrame으로 변환
            feature_df = pd.DataFrame([features])
            
            # 예측
            prediction = self.xgboost_model.predict(feature_df)
            probability = self.xgboost_model.predict_proba(feature_df)
            
            is_malicious = prediction[0] == 1
            confidence = float(probability[0][1]) if is_malicious else float(probability[0][0])
            
            return {
                "is_malicious": is_malicious,
                "confidence": confidence,
                "error": None
            }
            
        except Exception as e:
            logger.error(f"악성 코드 분석 실패: {e}")
            return {"is_malicious": False, "confidence": 0.0, "error": str(e)}
    
    def analyze_package(self, package_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        패키지 전체 분석
        
        Args:
            package_data: 패키지 데이터
            
        Returns:
            통합 분석 결과
        """
        try:
            # 취약점 분석
            vulnerability_result = self.analyze_vulnerability(package_data.get('code', ''))
            
            # 악성 코드 분석을 위한 특성 추출
            features = self._extract_features(package_data)
            malicious_result = self.analyze_malicious(features)
            
            return {
                "vulnerability": vulnerability_result,
                "malicious": malicious_result,
                "package_name": package_data.get('name', 'unknown'),
                "file_count": package_data.get('file_count', 0)
            }
            
        except Exception as e:
            logger.error(f"패키지 분석 실패: {e}")
            return {"error": str(e)}
    
    def _extract_features(self, package_data: Dict[str, Any]) -> Dict[str, Any]:
        """패키지에서 특성 추출"""
        features = {}
        
        # 기본 특성들
        features['file_count'] = package_data.get('file_count', 0)
        features['code_length'] = len(package_data.get('code', ''))
        features['line_count'] = package_data.get('code', '').count('\n')
        
        # 추가 특성들 (실제 구현에서는 더 많은 특성을 추출)
        features['import_count'] = package_data.get('code', '').count('import ')
        features['function_count'] = package_data.get('code', '').count('def ')
        features['class_count'] = package_data.get('code', '').count('class ')
        
        return features
    
    def cleanup(self):
        """리소스 정리"""
        try:
            self.lstm_model = None
            self.label_encoder = None
            self.xgboost_model = None
            self.w2v_model = None
            cleanup_memory()
            logger.info("분석기 리소스 정리 완료")
        except Exception as e:
            logger.error(f"리소스 정리 실패: {e}")

"""
LSTM-based malicious code analysis
Adapted from safepy_3_malicious/LSTM.py and preprocess.py
"""
import pickle
import os
import numpy as np
import tokenize
from io import BytesIO
from gensim.models import Word2Vec
from typing import Dict, Any, Optional
import time

class LSTMAnalyzer:
    def __init__(self, model_path: str = None, w2v_path: str = None):
        self.model_path = model_path
        self.w2v_path = w2v_path
        # Malicious detection models
        self.model = None
        self.label_encoder = None
        # Vulnerability detection models
        self.model_vul = None
        self.label_encoder_vul = None
        # CWE detection models
        self.model_cwe = None
        self.label_encoder_cwe = None
        self.w2v_model = None
        self.max_sequence_length = 100
        
        # Load models
        self._load_models()
    
    def _load_models(self):
        """Load LSTM models, label encoders, and Word2Vec model"""
        try:
            # Get base directory from model_path
            if self.model_path:
                base_dir = os.path.dirname(self.model_path)
            else:
                base_dir = None
            
            # Load malicious detection models
            if self.model_path and os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                print("LSTM malicious model loaded successfully")
            
            # Load malicious label encoder
            if base_dir:
                mal_label_encoder_path = os.path.join(base_dir, 'label_encoder_mal.pkl')
                if os.path.exists(mal_label_encoder_path):
                    with open(mal_label_encoder_path, 'rb') as f:
                        self.label_encoder = pickle.load(f)
                    print("Malicious label encoder loaded successfully")
            
            # Load vulnerability detection models
            if base_dir:
                vul_model_path = os.path.join(base_dir, 'model_vul.pkl')
                if os.path.exists(vul_model_path):
                    with open(vul_model_path, 'rb') as f:
                        self.model_vul = pickle.load(f)
                    print("LSTM vulnerability model loaded successfully")
                
                vul_label_encoder_path = os.path.join(base_dir, 'label_encoder_vul.pkl')
                if os.path.exists(vul_label_encoder_path):
                    with open(vul_label_encoder_path, 'rb') as f:
                        self.label_encoder_vul = pickle.load(f)
                    print("Vulnerability label encoder loaded successfully")
            
            # Load CWE detection models
            if base_dir:
                cwe_model_path = os.path.join(base_dir, 'model_cwe.pkl')
                if os.path.exists(cwe_model_path):
                    with open(cwe_model_path, 'rb') as f:
                        self.model_cwe = pickle.load(f)
                    print("LSTM CWE model loaded successfully")
                
                cwe_label_encoder_path = os.path.join(base_dir, 'label_encoder_cwe.pkl')
                if os.path.exists(cwe_label_encoder_path):
                    with open(cwe_label_encoder_path, 'rb') as f:
                        self.label_encoder_cwe = pickle.load(f)
                    print("CWE label encoder loaded successfully")
            
            # Load Word2Vec model
            if self.w2v_path and os.path.exists(self.w2v_path):
                self.w2v_model = Word2Vec.load(self.w2v_path)
                print("Word2Vec model loaded successfully")
            
        except Exception as e:
            print(f"Error loading LSTM models: {e}")
    
    def _tokenize_python(self, code_str: str) -> list:
        """Tokenize Python code using built-in tokenize module"""
        toks = []
        try:
            g = tokenize.tokenize(BytesIO(code_str.encode("utf-8")).readline)
            SKIP = {tokenize.ENCODING, tokenize.ENDMARKER, tokenize.NL}
            
            for toknum, tokval, _, _, _ in g:
                if toknum in SKIP:
                    continue
                if toknum == tokenize.COMMENT:
                    continue
                
                # Remove multiline strings (docstrings)
                if toknum == tokenize.STRING:
                    if (tokval.startswith('"""') and tokval.endswith('"""')) or \
                       (tokval.startswith("'''") and tokval.endswith("'''")):
                        continue
                
                if toknum == tokenize.NEWLINE:
                    toks.append("<EOL>")
                    continue
                if toknum == tokenize.INDENT:
                    toks.append("<INDENT>")
                    continue
                if toknum == tokenize.DEDENT:
                    toks.append("<DEDENT>")
                    continue
                
                toks.append(tokval)
        except (tokenize.TokenError, IndentationError, SyntaxError):
            pass
        return toks
    
    def _get_word_embedding(self, token: str) -> np.ndarray:
        """Get word embedding for token"""
        if self.w2v_model and token in self.w2v_model.wv:
            return self.w2v_model.wv[token]
        else:
            return np.zeros(self.w2v_model.vector_size) if self.w2v_model else np.zeros(100)
    
    def _embed_sequence(self, tokenized_sequence: list) -> np.ndarray:
        """Convert tokenized sequence to embedding sequence"""
        if not self.w2v_model:
            return np.array([])
        
        embedded_sequence = [self._get_word_embedding(token) for token in tokenized_sequence]
        embedded_sequence = [emb for emb in embedded_sequence if emb is not None]
        
        if embedded_sequence:
            return np.array(embedded_sequence)
        else:
            return np.array([])
    
    def _pad_sequence(self, embedded_sequence: np.ndarray) -> np.ndarray:
        """Pad sequence to fixed length"""
        if not self.w2v_model:
            return np.zeros((self.max_sequence_length, 100))
        
        embedding_dim = self.w2v_model.vector_size
        padded_code = np.zeros((self.max_sequence_length, embedding_dim))
        
        if embedded_sequence.shape[0] > 0:
            padding_length = self.max_sequence_length - embedded_sequence.shape[0]
            if padding_length > 0:
                padding = np.zeros((padding_length, embedding_dim))
                padded_code = np.concatenate((embedded_sequence, padding), axis=0)
            else:
                padded_code = embedded_sequence[:self.max_sequence_length]
        
        return padded_code
    
    def analyze_mal(self, code: str) -> Dict[str, Any]:
        """Analyze Python code for malicious patterns"""
        if not self.model or not self.label_encoder or not self.w2v_model:
            return {
                "is_malicious": False,
                "malicious_probability": 0.0,
                "lstm_label": "Unknown",
                "lstm_probability": 0.0,
                "error": "Models not loaded"
            }
        
        start_time = time.time()
        
        try:
            # Tokenize code
            tokenized_code = self._tokenize_python(code)
            
            # Embed sequence
            embedded_code = self._embed_sequence(tokenized_code)
            
            if embedded_code.size == 0:
                return {
                    "is_malicious": False,
                    "malicious_probability": 0.0,
                    "lstm_label": "Empty",
                    "lstm_probability": 0.0
                }
            
            # Pad sequence
            padded_code = self._pad_sequence(embedded_code)
            
            # Reshape for prediction (add batch dimension)
            padded_code = np.expand_dims(padded_code, axis=0)
            
            # Predict
            prediction = self.model.predict(padded_code)
            
            if prediction.ndim == 2 and prediction.shape[1] == 1:
                # Binary sigmoid
                predicted_index = int((prediction > 0.5).astype(int)[0][0])
            else:
                # Multiclass softmax
                predicted_index = int(np.argmax(prediction, axis=1)[0])
            
            # Decode label
            decoded_label = self.label_encoder.inverse_transform([predicted_index])[0]
            
            # Check if benign
            benign_aliases = {"Benign", "benign", "Not Vulnerable", "Normal", "Safe", "0", 0}
            is_benign = decoded_label in benign_aliases
            
            # Get probability
            if prediction.ndim == 2 and prediction.shape[1] == 1:
                malicious_prob = float(prediction[0][0])
            else:
                malicious_prob = float(np.max(prediction))
            
            analysis_time = time.time() - start_time
            
            return {
                "is_malicious": not is_benign,
                "malicious_probability": malicious_prob,
                "lstm_label": decoded_label,
                "lstm_probability": malicious_prob,
                "analysis_time": analysis_time
            }
            
        except Exception as e:
            return {
                "is_malicious": False,
                "malicious_probability": 0.0,
                "lstm_label": "Error",
                "lstm_probability": 0.0,
                "error": str(e)
            }
    
    def analyze_vul(self, code: str) -> Dict[str, Any]:
        """Analyze Python code for vulnerability patterns"""
        if not self.model_vul or not self.label_encoder_vul or not self.w2v_model:
            return {
                "is_vulnerable": False,
                "vulnerability_probability": 0.0,
                "cwe_label": "Unknown",
                "cwe_probability": 0.0,
                "error": "Vulnerability models not loaded"
            }
        
        start_time = time.time()
        
        try:
            # Tokenize code
            tokenized_code = self._tokenize_python(code)
            
            # Embed sequence
            embedded_code = self._embed_sequence(tokenized_code)
            
            if embedded_code.size == 0:
                return {
                    "is_vulnerable": False,
                    "vulnerability_probability": 0.0,
                    "cwe_label": "Empty",
                    "cwe_probability": 0.0
                }
            
            # Pad sequence
            padded_code = self._pad_sequence(embedded_code)
            
            # Reshape for prediction (add batch dimension)
            padded_code = np.expand_dims(padded_code, axis=0)
            
            # Step 1: Check if vulnerable using model_vul
            vul_prediction = self.model_vul.predict(padded_code)
            
            if vul_prediction.ndim == 2 and vul_prediction.shape[1] == 1:
                # Binary sigmoid
                predicted_vul_index = int((vul_prediction > 0.5).astype(int)[0][0])
            else:
                # Multiclass softmax
                predicted_vul_index = int(np.argmax(vul_prediction, axis=1)[0])
            
            # Decode vulnerability label
            decoded_vul_label = self.label_encoder_vul.inverse_transform([predicted_vul_index])[0]
            
            # Check if vulnerable
            vulnerable_aliases = {"Vulnerable", "vulnerable", "1", 1, "Vuln", "vuln"}
            is_vulnerable = decoded_vul_label in vulnerable_aliases
            
            # Get vulnerability probability
            if vul_prediction.ndim == 2 and vul_prediction.shape[1] == 1:
                vul_prob = float(vul_prediction[0][0])
            else:
                vul_prob = float(np.max(vul_prediction))
            
            cwe_label = "Benign"
            cwe_prob = 0.0
            
            # Step 2: If vulnerable, determine CWE type using model_cwe
            if is_vulnerable and self.model_cwe and self.label_encoder_cwe:
                cwe_prediction = self.model_cwe.predict(padded_code)
                
                if cwe_prediction.ndim == 2 and cwe_prediction.shape[1] == 1:
                    # Binary sigmoid
                    predicted_cwe_index = int((cwe_prediction > 0.5).astype(int)[0][0])
                else:
                    # Multiclass softmax
                    predicted_cwe_index = int(np.argmax(cwe_prediction, axis=1)[0])
                
                # Decode CWE label
                cwe_label = self.label_encoder_cwe.inverse_transform([predicted_cwe_index])[0]
                
                # Get CWE probability
                if cwe_prediction.ndim == 2 and cwe_prediction.shape[1] == 1:
                    cwe_prob = float(cwe_prediction[0][0])
                else:
                    cwe_prob = float(np.max(cwe_prediction))
            
            analysis_time = time.time() - start_time
            
            return {
                "is_vulnerable": is_vulnerable,
                "vulnerability_probability": vul_prob,
                "cwe_label": cwe_label,
                "cwe_probability": cwe_prob,
                "analysis_time": analysis_time
            }
            
        except Exception as e:
            return {
                "is_vulnerable": False,
                "vulnerability_probability": 0.0,
                "cwe_label": "Error",
                "cwe_probability": 0.0,
                "error": str(e)
            }

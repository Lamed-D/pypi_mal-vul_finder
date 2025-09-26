"""
전처리 유틸(safepy_3)
- tokenize_python: 파이썬 코드 토큰화(주석/멀티라인 문자열 제거)
- get_word_embedding / embed_sequences: Word2Vec 임베딩 변환
"""

import tokenize
from io import BytesIO
import os
import numpy as np

def tokenize_python(code_str, mask_string=True, mask_number=True):
    """파이썬 코드 토큰화(주석/멀티라인 문자열 제거, 들여쓰기 표식 유지)."""
    toks = []
    try:
        g = tokenize.tokenize(BytesIO(code_str.encode("utf-8")).readline)
        SKIP = {tokenize.ENCODING, tokenize.ENDMARKER, tokenize.NL}

        for toknum, tokval, _, _, _ in g:
            if toknum in SKIP:
                continue
            if toknum == tokenize.COMMENT:
                continue

            # 멀티라인 문자열(Docstring 추정) 제거
            if toknum == tokenize.STRING:
                if (tokval.startswith('"""') and tokval.endswith('"""')) or \
                   (tokval.startswith("'''") and tokval.endswith("'''")):
                    continue

            if toknum == tokenize.NEWLINE:
                toks.append("<EOL>"); continue
            if toknum == tokenize.INDENT:
                toks.append("<INDENT>"); continue # 코드 블럭 시작
            if toknum == tokenize.DEDENT:
                toks.append("<DEDENT>"); continue # 코드 블럭 끝

            # 일반 토큰 추가
            toks.append(tokval)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        # 코드가 불완전해서 tokenize 실패하는 경우 건너뜀
        pass
    return toks


from gensim.models import Word2Vec

# Get the current directory (where this script is located)
current_dir = os.path.dirname(os.path.abspath(__file__))

# Load the pre-trained Word2Vec model
# First try to find it in w2v directory, then current directory, then source directory
model_path = os.path.join(current_dir, 'w2v', 'word2vec_withString10-6-100.model')
if not os.path.exists(model_path):
    model_path = os.path.join(current_dir, 'word2vec_withString10-6-100.model')
    if not os.path.exists(model_path):
        model_path = os.path.join(current_dir, 'source', 'word2vec_withString10-6-100.model')
try:
    w2v_model = Word2Vec.load(model_path)
    print(f"Word2Vec model loaded successfully from {model_path}")
except FileNotFoundError:
    print(f"Error: Model file not found at {model_path}")
    w2v_model = None

def get_word_embedding(token, model):
    """단어 임베딩 벡터를 반환. OOV는 영벡터 반환."""
    if model and token in model.wv:
        return model.wv[token]
    else:
        # Return a zero vector for out-of-vocabulary words
        return np.zeros(model.vector_size) if model else None

def embed_sequences(tokenized_sequences, model):
    """토큰 시퀀스 리스트를 임베딩 시퀀스 리스트로 변환."""
    if not model:
        print("Word2Vec model not loaded. Cannot embed sequences.")
        return None

    embedded_sequences = []
    for sequence in tokenized_sequences:
        embedded_sequence = [get_word_embedding(token, model) for token in sequence]
        # Filter out None values if model wasn't loaded
        embedded_sequence = [emb for emb in embedded_sequence if emb is not None]
        if embedded_sequence:
             embedded_sequences.append(np.array(embedded_sequence))
        else:
            # Handle cases where a sequence results in no valid embeddings
            embedded_sequences.append(np.array([])) # Append an empty array or handle as needed

    return embedded_sequences

# 패딩은 분석 단계에서 고정 길이(예: 100)로 처리합니다.
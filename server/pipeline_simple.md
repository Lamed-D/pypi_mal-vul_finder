## PySecure 간단 파이프라인 (4단계)

`pipeline.md`와 제공하신 개념도를 바탕으로, 서버 전체 흐름을 4단계로 축약했습니다.

```mermaid
flowchart TB
  %% 1단계: 업로드/세션/추출
  subgraph S1 [1단계: 업로드/세션/추출]
    A[사용자 ZIP 업로드]
    B[파일 검증 - 확장자/크기]
    C[세션 생성 session_id]
    D[uploads/session_id/ 저장]
    E[압축 해제 - py 파일 추출]
    A --> B --> C --> D --> E
  end

  %% 2단계: 분석 (LSTM/BERT/ML)
  subgraph S2 [2단계: 분석]
    F{분석 모드 선택}
    G[LSTM<br/>Tokenizer -> Word2Vec -> 모델 예측]
    H[BERT<br/>CodeBERT 토크나이징 -> 예측]
    I[ML 패키지<br/>메타데이터 파싱 -> LSTM -> XGBoost -> 통합]
    F -->|LSTM| G
    F -->|BERT| H
    F -->|ML| I
  end

  %% 3단계: 결과 저장
  subgraph S3 [3단계: 결과 저장]
    J[(SQLite main.db)]
    K[세션 요약 main_log]
    L[세부 결과<br/>lstm_* / bert_* / pkg_vul_analysis]
    K --> J
    L --> J
  end

  %% 4단계: 시각화/조회
  subgraph S4 [4단계: 웹 대시보드/API 조회]
    M[대시보드/세션 페이지]
    N[REST API<br/>GET /sessions, /session/:id/...]
  end

  %% 그리드 배치: 상단 행(S1,S2), 하단 행(S3,S4)
  S1 --- S2
  S3 --- S4
  %% 상하 정렬 보조선(흐름 아님)
  S1 -.-> S3
  S2 -.-> S4

  %% 주요 흐름 강조: 1 -> 2 -> 3 -> 4
  S1 -->|1→2| S2
  S2 -->|2→3| S3
  S3 -->|3→4| S4
```

요약
- 1) 업로드·세션·추출: ZIP 업로드 → 검증 → session_id → 저장/추출
- 2) 분석: LSTM, BERT, 또는 ML(LSTM+XGBoost) 중 선택 수행
- 3) 결과 저장: `main_log`와 각 결과 테이블에 영구 저장
- 4) 시각화/조회: 대시보드와 REST API로 결과 확인



## PySecure Server Flow Charts (Mermaid)

A concise, step-by-step visualization of the PySecure server based on `pipeline.md`.

### 1) System Architecture (High Level)
```mermaid
graph LR
  A[Web UI<br/>(HTML/CSS/JS)] <--> B[FastAPI Server<br/>PySecure]
  B <--> C[AI Analysis Engine<br/>(LSTM / BERT / ML)]
  B <--> D[(SQLite DB<br/>main.db)]
```

### 2) End-to-End Upload & Analysis Flow
```mermaid
sequenceDiagram
  autonumber
  participant U as User (Browser)
  participant W as Web UI
  participant S as FastAPI (Routes)
  participant F as File Service
  participant L as LSTM/BERT Engine
  participant M as ML Package Analyzer
  participant DB as SQLite (main.db)

  U->>W: Select ZIP and model option
  W->>S: POST /api/v1/upload(/lstm|/bert|/ML)
  S->>F: Validate file, create session_id
  F->>F: Save to uploads/{session_id}/
  F->>F: Extract Python files
  alt LSTM/BERT analysis
    S->>L: Tokenize → Embed → Predict
    L-->>S: Vulnerable/Malicious results
  else ML package analysis (LSTM + XGBoost)
    S->>M: Parse metadata → LSTM → XGBoost → Integrate
    M-->>S: pkg_vul_analysis results
  end
  S->>DB: Persist session + results
  U->>W: Open dashboard/session pages
  W->>S: GET /session/{session_id}/(...)
  S-->>W: Render results (HTML)
```

### 3) Server Internal Processing Pipeline
```mermaid
flowchart TD
  A[ZIP upload] --> B[Validate file (ext/size)]
  B --> C[Create session_id]
  C --> D[Save ZIP → uploads/{session_id}/]
  D --> E[Extract → extracted/*.py]
  E --> F{Model mode?}
  F -->|LSTM| G[Tokenize → Word2Vec → LSTM predict]
  F -->|BERT| H[Tokenize → CodeBERT → Predict]
  F -->|ML (LSTM+XGB)| I[Parse metadata → LSTM → XGBoost → Integrate]
  G --> J[Compose results]
  H --> J
  I --> J
  J --> K[Persist to SQLite]
  K --> L[Render via templates]
```

### 4) API Endpoints Overview
```mermaid
flowchart LR
  subgraph Pages
    A1[GET /]:::page
    A2[GET /session/{id}]:::page
    A3[GET /session/{id}/vulnerable]:::page
    A4[GET /session/{id}/malicious]:::page
    A5[GET /session/{id}/ML]:::page
  end

  subgraph REST API
    B1[POST /api/v1/upload]:::api
    B2[POST /api/v1/upload/lstm]:::api
    B3[POST /api/v1/upload/bert]:::api
    B4[POST /api/v1/upload/ML]:::api
    B5[GET /api/v1/sessions]:::api
    B6[GET /api/v1/sessions/{id}]:::api
    B7[GET /api/v1/source/{id}/{path}]:::api
    B8[GET /api/v1/sessions/ML/{id}]:::api
    B9[GET /api/v1/sessions/ML/{id}/summary]:::api
    B10[GET /api/v1/stats]:::api
    B11[GET /health]:::api
  end

  classDef page fill:#E3F2FD,stroke:#1E88E5,stroke-width:1px,color:#0D47A1;
  classDef api fill:#E8F5E9,stroke:#43A047,stroke-width:1px,color:#1B5E20;
```

### 5) Database Entities (Simplified)
```mermaid
erDiagram
  MAIN_LOG ||--o{ LSTM_VUL : has
  MAIN_LOG ||--o{ LSTM_MAL : has
  MAIN_LOG ||--o{ LSTM_VUL_SAFE : has
  MAIN_LOG ||--o{ LSTM_MAL_SAFE : has
  MAIN_LOG ||--o{ BERT_VUL : has
  MAIN_LOG ||--o{ BERT_MAL : has
  MAIN_LOG ||--o{ BERT_VUL_SAFE : has
  MAIN_LOG ||--o{ BERT_MAL_SAFE : has
  MAIN_LOG ||--o{ PKG_VUL_ANALYSIS : has

  MAIN_LOG {
    string session_id PK
    datetime uploaded_at
    string filename
    boolean vul_flag
    boolean mal_flag
    boolean is_bert
    boolean is_mal
  }

  LSTM_VUL { string session_id FK }
  LSTM_MAL { string session_id FK }
  LSTM_VUL_SAFE { string session_id FK }
  LSTM_MAL_SAFE { string session_id FK }
  BERT_VUL { string session_id FK }
  BERT_MAL { string session_id FK }
  BERT_VUL_SAFE { string session_id FK }
  BERT_MAL_SAFE { string session_id FK }
  PKG_VUL_ANALYSIS {
    string session_id FK
    string package_name
    string summary
    string author
    string version
    int downloads
    string cwe_label
    float lstm_confidence
    boolean xgb_malicious
    float xgb_confidence
    string threat_level
  }
```

### 6) ML Package Analysis (LSTM + XGBoost)
```mermaid
flowchart TD
  A[ZIP Upload] --> B[Extract package]
  B --> C[Parse metadata (name, version, desc...)]
  C --> D[LSTM (code signals)]
  C --> E[XGBoost (package features)]
  D --> F[Integrate results]
  E --> F
  F --> G[Write to PKG_VUL_ANALYSIS]
  G --> H[Expose via /session/{id}/ML]
```

### 7) Runtime & Performance
```mermaid
flowchart LR
  A[FastAPI App] --> B[Workers (3)]
  B --> C[Parallel analysis jobs]
  C --> D[Streaming I/O & memory-efficient loads]
  D --> E[Results → DB → UI]
```

---

Tips:
- Render locally with Mermaid preview extensions or any Markdown viewer supporting Mermaid.
- Use this file alongside `pipeline.md` for details and narrative descriptions.



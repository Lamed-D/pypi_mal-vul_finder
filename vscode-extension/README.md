## Zip Uploader (Python Server)

### 개요
- VS Code에서 폴더를 ZIP으로 압축하고, 로컬 Python FastAPI 서버(`/upload`)에 업로드합니다.
- 서버는 받은 ZIP을 그대로 응답으로 돌려줍니다.

### 설치
```bash
cd vscode-extension
npm install
```

### 실행 순서
1) Python 서버 실행 (별도 폴더 `python-server` 참고)
2) VS Code에서 본 폴더를 열고 F5 (Run Extension)
3) Extension Development Host에서 명령 팔레트 → "Zip folder and upload to Python server"
4) 폴더 선택 → 저장할 경로 선택

### 설정
- 서버 주소: `http://127.0.0.1:8000/upload`



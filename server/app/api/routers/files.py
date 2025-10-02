"""소스 코드 조회 라우터."""

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from config import UPLOAD_DIR


router = APIRouter(prefix="/api/v1")


@router.get("/source/{session_id}/{file_path:path}")
async def get_source_code(session_id: str, file_path: str):
    try:
        normalized_file_path = file_path.replace("\\", "/")
        upload_dir = UPLOAD_DIR / session_id

        if not upload_dir.exists():
            raise HTTPException(status_code=404, detail="Session not found")

        search_dirs = [upload_dir / "extracted"]
        file_full_path: Path | None = None

        for extract_dir in search_dirs:
            path_parts = normalized_file_path.split("/")
            filename = path_parts[-1]

            possible_paths = {
                extract_dir / normalized_file_path,
                extract_dir / file_path,
                extract_dir / filename,
            }

            matching_files = list(extract_dir.rglob(f"*{filename}"))
            possible_paths.update(matching_files)

            exact_files = list(extract_dir.rglob(filename))
            possible_paths.update(exact_files)

            for path in possible_paths:
                if path.exists() and path.is_file():
                    file_full_path = path
                    break
            if file_full_path:
                break

        if not file_full_path:
            raise HTTPException(status_code=404, detail="File not found")

        with open(file_full_path, "r", encoding="utf-8") as source_file:
            content = source_file.read()
        return PlainTextResponse(content)
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=str(exc))

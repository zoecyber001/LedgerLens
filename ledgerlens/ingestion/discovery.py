import os
from pathlib import Path
from typing import Generator

from ledgerlens.models import DBEngineType, ScannedSchemaFile

ALLOWED_EXTENSIONS = {
    ".sql",
    ".prisma",
    ".hcl",
    ".tf",
    ".py",
    ".js",
    ".ts",
    ".json",
    ".yaml",
    ".yml",
}

IGNORED_DIRS = {
    "node_modules",
    "venv",
    ".venv",
    ".git",
    "dist",
    "build",
    "__pycache__",
}


def detect_engine_type(file_path: Path, content: str) -> DBEngineType:
    """
    Detects the database engine type based on file extension and content keywords.
    """
    ext = file_path.suffix.lower()

    if ext == ".prisma":
        return DBEngineType.PRISMA

    content_lower = content.lower()
    if "postgresql" in content_lower or "postgres" in content_lower:
        return DBEngineType.POSTGRESQL
    if "mysql" in content_lower:
        return DBEngineType.MYSQL
    if "sqlite" in content_lower:
        return DBEngineType.SQLITE

    return DBEngineType.GENERIC_SQL


def discover_schema_files(root: Path) -> Generator[ScannedSchemaFile, None, None]:
    """
    Recursively discover schema, DDL, migration, and ORM files in a target directory.

    Args:
        root: The root directory path to scan.

    Yields:
        ScannedSchemaFile objects representing discovered files.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        # Modify dirnames in-place to avoid traversing ignored directories
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]

        for filename in filenames:
            file_path = Path(dirpath) / filename
            if file_path.suffix.lower() in ALLOWED_EXTENSIONS:
                try:
                    content = file_path.read_text(encoding="utf-8")
                except Exception:
                    # Skip files that cannot be read as text
                    continue

                relative_path = str(file_path.relative_to(root))
                engine_type = detect_engine_type(file_path, content)

                yield ScannedSchemaFile(
                    path=file_path,
                    relative_path=relative_path,
                    engine_type=engine_type,
                    raw_content=content,
                )

"""Tests for ingestion module (discovery and archive)."""

from pathlib import Path

from ledgerlens.ingestion.archive import extract_archive
from ledgerlens.ingestion.discovery import discover_files


def test_discover_files(tmp_project: Path):
    files = list(discover_files(tmp_project))
    rel_paths = {f.relative_path for f in files}

    # Should discover config files
    assert ".env" in rel_paths
    assert "config/config.yaml" in rel_paths
    assert "Dockerfile" in rel_paths
    assert "infra/main.tf" in rel_paths

    # Should ignore node_modules
    for path in rel_paths:
        assert "node_modules" not in path


def test_extract_archive_zip(tmp_path: Path, tmp_project: Path):
    import zipfile

    archive_path = tmp_path / "test_repo.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.write(tmp_project / ".env", arcname=".env")
        zf.write(tmp_project / "config/config.yaml", arcname="config/config.yaml")

    with extract_archive(archive_path) as extracted_dir:
        files = list(discover_files(extracted_dir))
        rel_paths = {f.relative_path for f in files}
        assert ".env" in rel_paths
        assert "config/config.yaml" in rel_paths

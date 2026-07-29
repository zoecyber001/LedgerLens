import logging
import os
import shutil
import tarfile
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

# Imported as per instruction, even if indirectly used downstream
from ledgerlens.models import ScannedFile

logger = logging.getLogger(__name__)

MAX_ARCHIVE_SIZE_BYTES = 1024 * 1024 * 500  # 500 MB

class ArchiveExtractionError(Exception):
    """Exception raised for errors during archive extraction."""
    pass

def _is_safe_path(target_path: str, extract_dir: str) -> bool:
    """Ensure the target path resolves within the extraction directory."""
    extract_path = os.path.abspath(extract_dir)
    target = os.path.abspath(target_path)
    return target.startswith(extract_path + os.sep) or target == extract_path

def _extract_zip(archive_path: Path, temp_dir: str) -> None:
    """Extracts a zip file with zip-slip protection."""
    with zipfile.ZipFile(archive_path, 'r') as zf:
        for member in zf.namelist():
            target_path = os.path.join(temp_dir, member)
            if not _is_safe_path(target_path, temp_dir):
                raise ArchiveExtractionError(f"Zip-slip attempt detected: {member}")
        zf.extractall(temp_dir)

def _extract_tar(archive_path: Path, temp_dir: str) -> None:
    """Extracts a tar/tgz file with tar-slip protection."""
    with tarfile.open(archive_path, 'r:*') as tf:
        for member in tf.getmembers():
            target_path = os.path.join(temp_dir, member.name)
            if not _is_safe_path(target_path, temp_dir):
                raise ArchiveExtractionError(f"Tar-slip attempt detected: {member.name}")
        
        # In Python 3.12+, extractall supports a 'filter' argument for safety.
        # This fallback is compatible with Python 3.11 with manual validation.
        tf.extractall(temp_dir)

@contextmanager
def extract_archive(archive_path: Path) -> Generator[Path, None, None]:
    """
    Extracts a supported archive (.zip, .tar.gz, .tgz) into a secure temporary directory.
    Validates archive against zip-slip/tar-slip attacks and size constraints.
    Yields the Path to the extracted directory, which is cleaned up upon context exit.
    
    Args:
        archive_path: Path to the archive file.
        
    Yields:
        Path to the secure temporary directory containing extracted contents.
        
    Raises:
        FileNotFoundError: If the archive does not exist.
        ArchiveExtractionError: If the archive is invalid or extraction fails.
    """
    if not archive_path.is_file():
        raise FileNotFoundError(f"Archive not found: {archive_path}")

    if archive_path.stat().st_size > MAX_ARCHIVE_SIZE_BYTES:
        raise ArchiveExtractionError(f"Archive exceeds max size of {MAX_ARCHIVE_SIZE_BYTES} bytes")

    temp_dir = tempfile.mkdtemp(prefix="ledgerlens_archive_")
    
    try:
        if archive_path.name.lower().endswith(".zip"):
            _extract_zip(archive_path, temp_dir)
        elif archive_path.name.lower().endswith((".tar.gz", ".tgz")):
            _extract_tar(archive_path, temp_dir)
        else:
            raise ArchiveExtractionError(f"Unsupported archive format: {archive_path}")
            
        yield Path(temp_dir)
    except Exception as e:
        logger.error(f"Failed to extract archive {archive_path}: {e}")
        raise ArchiveExtractionError(f"Extraction failed: {e}") from e
    finally:
        # Secure cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)

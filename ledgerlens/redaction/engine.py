from typing import Generator, Iterable

from ledgerlens.models import (
    RedactedContent,
    RedactionHit,
    ScannedSchemaFile,
)
from ledgerlens.redaction.patterns import ALL_PATTERNS


def _mask_snippet(snippet: str) -> str:
    """Masks a matched snippet by keeping only the first 4 characters and appending ***."""
    if len(snippet) > 4:
        return snippet[:4] + "***"
    return snippet + "***"


def redact_schema_file(file: ScannedSchemaFile) -> RedactedContent:
    """
    Processes a schema file line-by-line, redacting matched secrets.
    """
    redacted_lines = []
    hits = []
    
    # Process line-by-line
    lines = file.raw_content.splitlines(keepends=True)
    for line_idx, line in enumerate(lines):
        current_line = line
        line_number = line_idx + 1
        
        for pattern_def in ALL_PATTERNS:
            # Find all occurrences in the line to record hits before subbing
            for match in pattern_def.pattern.finditer(current_line):
                matched_text = match.group(0)
                redacted_marker = f"[REDACTED:{pattern_def.category.name}]"
                
                hits.append(RedactionHit(
                    line_number=line_number,
                    category=pattern_def.category,
                    original_snippet=_mask_snippet(matched_text),
                    redacted_snippet=redacted_marker,
                    pattern_name=pattern_def.name
                ))
            
            # Sub the actual occurrences in the line string
            if pattern_def.pattern.search(current_line):
                redacted_marker = f"[REDACTED:{pattern_def.category.name}]"
                current_line = pattern_def.pattern.sub(redacted_marker, current_line)
            
        redacted_lines.append(current_line)

    redacted_text = "".join(redacted_lines)
    
    return RedactedContent(
        file=file,
        redacted_text=redacted_text,
        hits=hits
    )


def redact_schema_files(files: Iterable[ScannedSchemaFile]) -> Generator[RedactedContent, None, None]:
    """
    Processes an iterable of schema files, yielding redacted content for each.
    """
    for file in files:
        yield redact_schema_file(file)

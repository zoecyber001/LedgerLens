"""Chronological Migration Chain Reconstitution Engine for LedgerLens v2.0."""

import logging
import re
from pathlib import Path
from typing import Dict, List

from ledgerlens.ingestion.ast_parser import parse_sql_ast
from ledgerlens.models import DBEngineType, ScannedSchemaFile, TableDef


log = logging.getLogger("ledgerlens.migration_replayer")


class MigrationChainReplayer:
    """Replays chronological database migrations to compute the final unified database schema state."""

    @classmethod
    def reconstitute_migration_chain(cls, schema_files: List[ScannedSchemaFile]) -> ScannedSchemaFile:
        """Sorts migration files chronologically and computes the unified final database state.

        Args:
            schema_files: List of discovered ScannedSchemaFile objects.

        Returns:
            A single ScannedSchemaFile containing the unified final database schema.
        """
        if not schema_files:
            return ScannedSchemaFile(
                path=Path("unified_schema.sql"),
                relative_path="unified_schema.sql",
                engine_type=DBEngineType.POSTGRESQL,
                raw_content="",
                tables=[],
            )

        sorted_files = sorted(schema_files, key=lambda f: f.relative_path)
        table_map: Dict[str, TableDef] = {}

        for sf in sorted_files:
            parsed_sf = parse_sql_ast(sf)
            for table in parsed_sf.tables:
                table_map[table.name.lower().strip('"`')] = table

            cls._replay_alter_statements(sf.raw_content, table_map)

        unified_tables = list(table_map.values())

        return ScannedSchemaFile(
            path=sorted_files[0].path if sorted_files else Path("unified_schema.sql"),
            relative_path="reconstituted_final_schema.sql",
            engine_type=sorted_files[0].engine_type if sorted_files else DBEngineType.POSTGRESQL,
            raw_content="\n\n".join(sf.raw_content for sf in sorted_files),
            tables=unified_tables,
        )

    # Alias for backward compatibility
    Reconstitute_migration_chain = reconstitute_migration_chain

    @classmethod
    def _replay_alter_statements(cls, raw_sql: str, table_map: Dict[str, TableDef]) -> None:
        """Applies ALTER TABLE schema modifications to the active in-memory table state."""
        add_col_pattern = re.compile(
            r"ALTER\s+TABLE\s+([^\s;]+)\s+ADD\s+(?:COLUMN\s+)?([^\s;]+)\s+([^\s;,]+)",
            re.IGNORECASE
        )
        for match in add_col_pattern.finditer(raw_sql):
            tbl_name = match.group(1).lower().strip('"`')
            col_name = match.group(2).strip('"`')
            col_type = match.group(3)

            if tbl_name in table_map:
                table_def = table_map[tbl_name]
                col_exists = False
                for c in table_def.columns:
                    if c.name.lower() == col_name.lower():
                        c.data_type = col_type
                        col_exists = True
                        break
                if not col_exists:
                    from ledgerlens.models import ColumnDef
                    table_def.columns.append(ColumnDef(name=col_name, data_type=col_type))

        drop_col_pattern = re.compile(
            r"ALTER\s+TABLE\s+([^\s;]+)\s+DROP\s+(?:COLUMN\s+)?([^\s;,]+)",
            re.IGNORECASE
        )
        for match in drop_col_pattern.finditer(raw_sql):
            tbl_name = match.group(1).lower().strip('"`')
            col_name = match.group(2).lower().strip('"`')

            if tbl_name in table_map:
                table_def = table_map[tbl_name]
                table_def.columns = [c for c in table_def.columns if c.name.lower() != col_name]

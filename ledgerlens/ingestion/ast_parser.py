"""Production SQL AST Parser using sqlglot for LedgerLens v2.0."""

import logging
from typing import List, Optional

import sqlglot
from sqlglot import exp

from ledgerlens.models import ColumnDef, DBEngineType, ScannedSchemaFile, TableDef

log = logging.getLogger("ledgerlens.ast_parser")

LEDGER_KEYWORDS = {
    "ledger", "transaction", "balance", "entry", "journal", "payment",
    "payout", "wallet", "account_balance", "audit_log", "transfer", "settlement"
}


def parse_sql_ast(scanned_file: ScannedSchemaFile) -> ScannedSchemaFile:
    """Parses SQL DDL text into structured TableDef and ColumnDef models using sqlglot AST parsing.

    Args:
        scanned_file: ScannedSchemaFile containing raw SQL content.

    Returns:
        Populated ScannedSchemaFile with AST-extracted tables and constraints.
    """
    raw_content = scanned_file.raw_content
    if not raw_content or not raw_content.strip():
        return scanned_file

    dialect = "postgres"
    if scanned_file.engine_type == DBEngineType.MYSQL:
        dialect = "mysql"
    elif scanned_file.engine_type == DBEngineType.SQLITE:
        dialect = "sqlite"

    try:
        parsed_expressions = sqlglot.parse(raw_content, read=dialect)
    except Exception as err:
        log.debug("sqlglot dialect parsing fallback to default: %s", err)
        try:
            parsed_expressions = sqlglot.parse(raw_content)
        except Exception:
            parsed_expressions = []

    tables: List[TableDef] = []

    for expr in parsed_expressions:
        if not expr:
            continue

        # Handle CREATE TABLE AST node
        if isinstance(expr, exp.Create) and isinstance(expr.this, exp.Schema):
            table_name = expr.this.this.name
            table_def = _extract_table_def_from_create_ast(table_name, expr)
            tables.append(table_def)

    scanned_file.tables = tables
    return scanned_file


def _extract_table_def_from_create_ast(table_name: str, create_expr: exp.Create) -> TableDef:
    """Extracts columns, data types, and constraints from a CREATE TABLE AST node."""
    columns: List[ColumnDef] = []
    constraints: List[str] = []

    schema_node = create_expr.this
    if isinstance(schema_node, exp.Schema):
        for col_expr in schema_node.expressions:
            if isinstance(col_expr, exp.ColumnDef):
                col_name = col_expr.name
                col_type = str(col_expr.kind) if col_expr.kind else "TEXT"

                is_pk = False
                is_nullable = True

                for constraint in col_expr.constraints:
                    c_kind = constraint.kind
                    if isinstance(c_kind, exp.PrimaryKeyColumnConstraint):
                        is_pk = True
                        is_nullable = False
                    elif isinstance(c_kind, exp.NotNullColumnConstraint):
                        is_nullable = False

                columns.append(ColumnDef(
                    name=col_name,
                    data_type=col_type,
                    is_nullable=is_nullable,
                    is_primary_key=is_pk,
                ))

            elif isinstance(col_expr, exp.Check):
                constraints.append(f"CHECK ({col_expr.sql()})")
            elif isinstance(col_expr, exp.ForeignKey):
                constraints.append(f"FOREIGN KEY ({col_expr.sql()})")
            elif isinstance(col_expr, exp.Constraint):
                constraints.append(f"CONSTRAINT {col_expr.sql()}")

    name_lower = table_name.lower()
    is_ledger = any(kw in name_lower for kw in LEDGER_KEYWORDS)

    return TableDef(
        name=table_name,
        columns=columns,
        constraints=constraints,
        is_ledger_table=is_ledger,
    )

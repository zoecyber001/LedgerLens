import re

from ledgerlens.models import DBEngineType, ScannedSchemaFile, TableDef, ColumnDef

LEDGER_KEYWORDS = {
    "ledger", "transaction", "balance", "entry", "journal", "payment",
    "payout", "wallet", "account_balance", "audit_log", "transfer"
}

CREATE_TABLE_PATTERN = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_\"'`\.]+)\s*\((.*?)\)(?:;|(?=\s*CREATE|\s*$))",
    re.IGNORECASE | re.DOTALL
)

CREATE_TRIGGER_PATTERN = re.compile(
    r"(CREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER\s+[a-zA-Z0-9_\"'`\.]+\s+(?:BEFORE|AFTER|INSTEAD\s+OF)\s+(?:UPDATE|DELETE|INSERT)\s+(?:OR\s+(?:UPDATE|DELETE|INSERT)\s+)*ON\s+[a-zA-Z0-9_\"'`\.]+.*?)(?:;|$)",
    re.IGNORECASE | re.DOTALL
)

PRISMA_MODEL_PATTERN = re.compile(
    r"model\s+([a-zA-Z0-9_]+)\s*\{([^}]*)\}",
    re.DOTALL
)


def is_ledger_table(table_name: str) -> bool:
    """Check if the table name indicates a financial ledger table."""
    name_lower = table_name.lower()
    return any(kw in name_lower for kw in LEDGER_KEYWORDS)


def _split_sql_elements(body: str) -> list[str]:
    """Helper to split SQL table body elements safely accounting for parentheses."""
    elements = []
    current = []
    paren_depth = 0
    for char in body:
        if char == '(':
            paren_depth += 1
            current.append(char)
        elif char == ')':
            paren_depth -= 1
            current.append(char)
        elif char == ',' and paren_depth == 0:
            elements.append("".join(current))
            current = []
        else:
            current.append(char)
    if current:
        elements.append("".join(current))
    return elements


def _parse_sql(content: str) -> list[TableDef]:
    tables = []
    # Strip block comments for easier parsing
    content_no_comments = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
    # Strip inline comments
    content_no_comments = re.sub(r'--.*$', '', content_no_comments, flags=re.MULTILINE)
    
    triggers = []
    for trigger_match in CREATE_TRIGGER_PATTERN.finditer(content_no_comments):
        triggers.append(trigger_match.group(1).strip())
        
    for match in CREATE_TABLE_PATTERN.finditer(content_no_comments):
        table_name = match.group(1).strip('`"\'')
        body = match.group(2)
        
        columns = []
        constraints = []
        
        elements = _split_sql_elements(body)
        for element in elements:
            element = element.strip()
            if not element:
                continue
            upper_el = element.upper()
            if (upper_el.startswith('CONSTRAINT') or 
                upper_el.startswith('PRIMARY KEY') or 
                upper_el.startswith('FOREIGN KEY') or 
                upper_el.startswith('UNIQUE') or 
                upper_el.startswith('CHECK')):
                constraints.append(element)
            else:
                # Column def
                parts = element.split()
                if len(parts) >= 2:
                    col_name = parts[0].strip('`"\'')
                    col_type = parts[1]
                    
                    is_nullable = 'NOT NULL' not in upper_el
                    is_pk = 'PRIMARY KEY' in upper_el
                    is_fk = 'REFERENCES' in upper_el
                    ref = None
                    
                    if is_fk:
                        ref_match = re.search(r'REFERENCES\s+([a-zA-Z0-9_\"\'`\.]+)\s*(?:\([^)]+\))?', element, re.IGNORECASE)
                        if ref_match:
                            ref = ref_match.group(1).strip('`"\'')
                            
                    columns.append(ColumnDef(
                        name=col_name,
                        data_type=col_type,
                        is_nullable=is_nullable,
                        is_primary_key=is_pk,
                        is_foreign_key=is_fk,
                        references=ref
                    ))
                    
        # Associate triggers that contain table_name
        table_triggers = [
            t for t in triggers 
            if f'ON {table_name}' in t or f'ON `{table_name}`' in t or f'ON "{table_name}"' in t
        ]
        
        tables.append(TableDef(
            name=table_name,
            columns=columns,
            constraints=constraints,
            triggers=table_triggers,
            is_ledger_table=is_ledger_table(table_name)
        ))
        
    return tables


def _parse_prisma(content: str) -> list[TableDef]:
    tables = []
    for match in PRISMA_MODEL_PATTERN.finditer(content):
        table_name = match.group(1).strip()
        body = match.group(2)
        columns = []
        
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('@@'):
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                col_name = parts[0]
                col_type = parts[1]
                is_nullable = '?' in col_type
                is_pk = '@id' in line
                is_fk = '@relation' in line
                
                ref = None
                if is_fk:
                    ref_match = re.search(r'@relation\([^)]*references:\s*\[([^\]]+)\]', line)
                    if ref_match:
                        ref = ref_match.group(1).strip()
                        
                columns.append(ColumnDef(
                    name=col_name,
                    data_type=col_type.replace('?', ''),
                    is_nullable=is_nullable,
                    is_primary_key=is_pk,
                    is_foreign_key=is_fk,
                    references=ref
                ))
                
        tables.append(TableDef(
            name=table_name,
            columns=columns,
            is_ledger_table=is_ledger_table(table_name)
        ))
    return tables


def parse_schema_file(scanned_file: ScannedSchemaFile) -> ScannedSchemaFile:
    """
    Parses raw SQL DDL and Prisma schema text into structured TableDef and ColumnDef objects.
    Populates the scanned_file.tables list.

    Args:
        scanned_file: The schema file to parse.

    Returns:
        The updated ScannedSchemaFile with parsed tables.
    """
    if scanned_file.engine_type == DBEngineType.PRISMA:
        scanned_file.tables = _parse_prisma(scanned_file.raw_content)
    else:
        scanned_file.tables = _parse_sql(scanned_file.raw_content)
        
    return scanned_file

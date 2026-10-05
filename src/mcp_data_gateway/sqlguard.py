"""Deciding whether a statement may run, and rewriting it so it is bounded.

Every published analysis of MCP database incidents lands on the same cause: a
tool that accepts free-form SQL against a connection with more privilege than
the question needed. The usual mitigation offered is a read-only database user,
which is necessary and not sufficient - a read-only role still permits reading
every row of every table it can see, which is the exfiltration case.

So statements are parsed into an abstract syntax tree and inspected, never
pattern-matched. Regular expressions over SQL are defeated by comments, nested
sub-selects, unions, and whitespace; an AST is defeated by none of those,
because it describes what the statement *does* rather than how it is spelled.

The guard is deliberately conservative. Anything it cannot prove safe is
refused with a reason, because the cost of a wrong refusal is a confused user
and the cost of a wrong approval is a breach.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp

from .policy import Role, TableRule

#: Statement types that read. Anything else is refused outright rather than
#: inspected further, because the safe set is small and easy to enumerate.
READ_STATEMENTS = (exp.Select, exp.Union, exp.Subquery)

#: Functions that reach outside the query engine: the filesystem, the network,
#: another database, or the server's own execution. None belong in a question
#: about business data.
DANGEROUS_FUNCTIONS = frozenset({
    "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
    "lo_import", "lo_export", "dblink", "dblink_exec", "copy",
    "pg_sleep", "pg_terminate_backend", "pg_cancel_backend",
    "load_extension", "readfile", "writefile", "edit", "fts3_tokenizer",
    "system", "shell", "exec", "xp_cmdshell",
})

#: Schemas describing the database itself. Reading them reveals structure a
#: role was never granted, and they are a standard reconnaissance step.
SYSTEM_SCHEMAS = frozenset({
    "pg_catalog", "information_schema", "pg_toast", "sys", "mysql", "performance_schema",
})

#: SQLite's catalogue is a table name rather than a schema.
SYSTEM_TABLES = frozenset({"sqlite_master", "sqlite_schema", "sqlite_temp_master"})


@dataclass(frozen=True)
class GuardDecision:
    """The verdict on one statement, and why."""

    allowed: bool
    reasons: tuple[str, ...] = ()
    sql: str | None = None
    tables: tuple[str, ...] = ()
    applied_limit: int | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def refuse(cls, *reasons: str) -> GuardDecision:
        return cls(allowed=False, reasons=tuple(reasons))


def _table_name(table: exp.Table) -> str:
    parts = [part.name for part in (table.args.get("db"), table.this) if part is not None]
    return ".".join(p for p in parts if p).lower()


def _schema_of(table: exp.Table) -> str | None:
    db = table.args.get("db")
    return db.name.lower() if db is not None else None


def guard(sql: str, role: Role, *, dialect: str = "postgres") -> GuardDecision:
    """Decide whether `sql` may run for `role`, and bound it if so."""
    if not sql or not sql.strip():
        return GuardDecision.refuse("empty statement")

    try:
        statements = sqlglot.parse(sql, dialect=dialect)
    except Exception as error:  # noqa: BLE001 - any parse failure is a refusal
        return GuardDecision.refuse(f"could not parse the statement: {error}")

    # sqlglot yields None for an empty statement, so these are dropped into a
    # new list rather than reassigned: narrowing a variable in place loses it.
    parsed = [s for s in statements if s is not None]
    if not parsed:
        return GuardDecision.refuse("no statement found")
    if len(parsed) > 1:
        return GuardDecision.refuse(
            f"{len(parsed)} statements submitted; exactly one is allowed"
        )

    tree = parsed[0]
    reasons: list[str] = []

    # 1. Reads only. A CTE is permitted, but only when it wraps a read.
    root = tree.this if isinstance(tree, exp.Subquery) else tree
    if isinstance(root, exp.With):
        root = root.this
    if not isinstance(root, READ_STATEMENTS):
        return GuardDecision.refuse(
            f"only SELECT statements are allowed; this is {type(root).__name__.upper()}"
        )

    # 2. No write or schema-change node anywhere, including inside CTEs, which
    #    is how a write hides behind a statement that parses as a read.
    writes = (exp.Insert, exp.Update, exp.Delete, exp.Drop, exp.Create, exp.Alter,
              exp.Merge, exp.TruncateTable, exp.Grant, exp.Command)
    for node in tree.find_all(*writes):
        return GuardDecision.refuse(
            f"statement contains a {type(node).__name__.upper()} operation"
        )

    # 3. SELECT ... INTO writes a table while parsing as a read.
    if tree.find(exp.Into):
        return GuardDecision.refuse("SELECT ... INTO writes to a table")

    # 4. Functions that reach outside the query engine, at any depth. An
    #    unrecognised function parses as Anonymous and carries its name as a
    #    string; a recognised one is a typed node and reports its own name.
    for func in tree.find_all(exp.Func):
        name = _function_name(func)
        if name in DANGEROUS_FUNCTIONS:
            return GuardDecision.refuse(f"function {name} is not permitted")

    # 5. Tables: every one must be allowlisted for this role.
    tables = [t for t in tree.find_all(exp.Table)]
    cte_names = {cte.alias_or_name.lower() for cte in tree.find_all(exp.CTE)}
    referenced: list[str] = []
    for table in tables:
        name = _table_name(table)
        bare = table.name.lower()
        if bare in cte_names:
            continue  # a reference to a CTE defined in this statement
        schema = _schema_of(table)
        if schema in SYSTEM_SCHEMAS or bare in SYSTEM_TABLES:
            return GuardDecision.refuse(f"{name or bare} is a system catalogue")
        lookup = bare if role.rule_for(bare) else name
        if not role.permits_table(lookup):
            reasons.append(f"table {name or bare} is not available to role {role.name}")
        else:
            referenced.append(lookup)

    if reasons:
        return GuardDecision(allowed=False, reasons=tuple(reasons))
    if not referenced:
        return GuardDecision.refuse("statement reads no permitted table")

    # 6. Columns, where the role restricts them.
    column_reasons = _check_columns(tree, role, referenced)
    if column_reasons:
        return GuardDecision(allowed=False, reasons=tuple(column_reasons))

    # 7. Bound the result. A missing or oversized limit is corrected rather
    #    than refused: the intent is legitimate, only the size is not.
    notes: list[str] = []
    applied = _apply_limit(root, role.max_rows, notes)

    return GuardDecision(
        allowed=True,
        sql=tree.sql(dialect=dialect),
        tables=tuple(sorted(set(referenced))),
        applied_limit=applied,
        notes=tuple(notes),
    )


def _function_name(func: exp.Func) -> str:
    """The name a function was written with, lowercased."""
    if isinstance(func, exp.Anonymous):
        name = func.this
        return str(name).lower() if name else ""
    try:
        return (func.sql_name() or "").lower()
    except Exception:  # noqa: BLE001 - an unnamed node is simply not a match
        return ""


def _alias_map(tree: exp.Expr) -> dict[str, str]:
    """Map every alias and bare name in the statement to its real table.

    Without this, a column rule is trivially bypassed by aliasing: the rule is
    attached to `customers`, while the column is written `c.email`.
    """
    mapping: dict[str, str] = {}
    for table in tree.find_all(exp.Table):
        real = table.name.lower()
        mapping[real] = real
        alias = table.alias
        if alias:
            mapping[alias.lower()] = real
    return mapping


def _check_columns(tree: exp.Expr, role: Role, referenced: list[str]) -> list[str]:
    """Refuse columns the role may not read, and unexpandable wildcards."""
    reasons: list[str] = []
    rules = [role.rule_for(name) for name in referenced]
    restricted = [r for r in rules if r is not None and r.has_restrictions]

    if tree.find(exp.Star) and restricted:
        names = ", ".join(sorted(r.name for r in restricted))
        reasons.append(
            f"SELECT * cannot be checked against column rules on {names}; name the columns"
        )

    if not restricted:
        return reasons

    aliases = _alias_map(tree)
    # An unqualified column is only unambiguous when the statement reads one table.
    single: TableRule | None = rules[0] if len(set(referenced)) == 1 else None

    for column in tree.find_all(exp.Column):
        qualifier = column.table.lower()
        if qualifier:
            rule = role.rule_for(aliases.get(qualifier, qualifier))
        else:
            rule = single
        if rule is None:
            continue
        if not rule.permits_column(column.name):
            reasons.append(f"column {rule.name}.{column.name} is not available to role {role.name}")
    return reasons


def _apply_limit(root: exp.Expr, max_rows: int, notes: list[str]) -> int | None:
    """Force a bounded result, lowering any limit that exceeds the role's cap."""
    existing = root.args.get("limit") if hasattr(root, "args") else None
    if existing is None:
        root.set("limit", exp.Limit(expression=exp.Literal.number(max_rows)))
        notes.append(f"no limit given; capped at {max_rows} rows")
        return max_rows

    try:
        current = int(existing.expression.name)
    except (AttributeError, ValueError):
        root.set("limit", exp.Limit(expression=exp.Literal.number(max_rows)))
        notes.append(f"limit was not a plain number; replaced with {max_rows}")
        return max_rows

    if current > max_rows:
        existing.set("expression", exp.Literal.number(max_rows))
        notes.append(f"limit {current} exceeds the cap for this role; lowered to {max_rows}")
        return max_rows
    return current

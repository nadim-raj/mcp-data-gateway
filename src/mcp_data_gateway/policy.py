"""Roles, and what each one is allowed to see.

Access is defined per organisation, per role, and is deliberately expressed as
an allowlist. A denylist answers "what have we thought to forbid"; an allowlist
answers "what have we decided to permit", and only the second is safe when the
thing on the other side is a language model improvising queries.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

DEFAULT_MAX_ROWS = 500
DEFAULT_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True)
class TableRule:
    """What a role may read from one table."""

    name: str
    #: Columns the role may read. Empty means every column except those denied.
    allowed_columns: frozenset[str] = frozenset()
    #: Columns the role may never read, whatever else is permitted.
    denied_columns: frozenset[str] = frozenset()

    def permits_column(self, column: str) -> bool:
        column = column.lower()
        if column in {c.lower() for c in self.denied_columns}:
            return False
        if not self.allowed_columns:
            return True
        return column in {c.lower() for c in self.allowed_columns}

    @property
    def has_restrictions(self) -> bool:
        """True when `SELECT *` cannot be verified safe without expansion."""
        return bool(self.allowed_columns or self.denied_columns)


@dataclass(frozen=True)
class Role:
    """A named set of permissions inside one organisation."""

    name: str
    tables: Mapping[str, TableRule] = field(default_factory=dict)
    max_rows: int = DEFAULT_MAX_ROWS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    #: Free-form SELECT is a privilege, not a default. Roles without it get the
    #: curated tools only.
    allow_free_sql: bool = False

    def rule_for(self, table: str) -> TableRule | None:
        return self.tables.get(table.lower())

    def permits_table(self, table: str) -> bool:
        return table.lower() in self.tables

    @property
    def table_names(self) -> tuple[str, ...]:
        return tuple(sorted(self.tables))


@dataclass(frozen=True)
class Organisation:
    """One tenant: an identity provider, an allowlist of people, and roles."""

    slug: str
    issuer: str
    audience: str
    roles: Mapping[str, Role]
    #: Email addresses permitted to use this organisation, mapped to a role.
    members: Mapping[str, str] = field(default_factory=dict)
    default_role: str | None = None

    def role_for_email(self, email: str) -> Role | None:
        """Resolve a verified email address to a role.

        Matching is case-insensitive because identity providers are not
        consistent about case, and an allowlist that misses because somebody
        capitalised their address is an outage, not a control.
        """
        if not email:
            return None
        assigned = self.members.get(email.strip().lower())
        if assigned is None:
            assigned = self.default_role
        if assigned is None:
            return None
        return self.roles.get(assigned)

    def is_member(self, email: str) -> bool:
        return self.role_for_email(email) is not None


def build_role(
    name: str,
    tables: Iterable[TableRule],
    *,
    max_rows: int = DEFAULT_MAX_ROWS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    allow_free_sql: bool = False,
) -> Role:
    return Role(
        name=name,
        tables={rule.name.lower(): rule for rule in tables},
        max_rows=max_rows,
        timeout_seconds=timeout_seconds,
        allow_free_sql=allow_free_sql,
    )

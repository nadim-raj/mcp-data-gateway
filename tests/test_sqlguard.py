import pytest

from mcp_data_gateway.sqlguard import guard


class TestReadsAreAllowed:
    def test_simple_select(self, analyst):
        decision = guard("SELECT id, total FROM orders", analyst)
        assert decision.allowed, decision.reasons
        assert decision.tables == ("orders",)

    def test_join_between_permitted_tables(self, analyst):
        sql = "SELECT o.id FROM orders o JOIN customers c ON c.id = o.customer_id"
        assert guard(sql, analyst).allowed

    def test_cte_wrapping_a_read(self, analyst):
        sql = "WITH recent AS (SELECT * FROM orders) SELECT id FROM recent"
        assert guard(sql, analyst).allowed

    def test_star_allowed_when_table_has_no_column_rules(self, analyst):
        assert guard("SELECT * FROM orders", analyst).allowed


class TestLimits:
    def test_missing_limit_is_added(self, analyst):
        decision = guard("SELECT id FROM orders", analyst)
        assert decision.applied_limit == 100
        assert "limit" in decision.sql.lower()
        assert any("capped" in note for note in decision.notes)

    def test_oversized_limit_is_lowered(self, analyst):
        decision = guard("SELECT id FROM orders LIMIT 100000", analyst)
        assert decision.applied_limit == 100
        assert "100000" not in decision.sql

    def test_modest_limit_is_respected(self, analyst):
        decision = guard("SELECT id FROM orders LIMIT 10", analyst)
        assert decision.applied_limit == 10


class TestWritesAreRefused:
    @pytest.mark.parametrize("sql", [
        "INSERT INTO orders (id) VALUES (1)",
        "UPDATE orders SET total = 0",
        "DELETE FROM orders",
        "DROP TABLE orders",
        "CREATE TABLE x (id INT)",
        "ALTER TABLE orders ADD COLUMN x INT",
        "TRUNCATE TABLE orders",
        "GRANT SELECT ON orders TO PUBLIC",
    ])
    def test_write_statements(self, analyst, sql):
        decision = guard(sql, analyst)
        assert not decision.allowed
        assert decision.reasons

    def test_write_hidden_in_a_cte(self, analyst):
        sql = "WITH x AS (INSERT INTO orders (id) VALUES (1) RETURNING id) SELECT * FROM x"
        assert not guard(sql, analyst).allowed

    def test_select_into_writes_a_table(self, analyst):
        assert not guard("SELECT * INTO copy_of_orders FROM orders", analyst).allowed


class TestInjectionShapes:
    def test_second_statement_is_refused(self, analyst):
        decision = guard("SELECT id FROM orders; DROP TABLE orders", analyst)
        assert not decision.allowed
        assert "exactly one" in decision.reasons[0]

    def test_comment_does_not_hide_a_second_statement(self, analyst):
        sql = "SELECT id FROM orders; -- harmless\nDELETE FROM orders"
        assert not guard(sql, analyst).allowed

    def test_union_to_a_forbidden_table(self, analyst):
        sql = "SELECT id FROM orders UNION SELECT id FROM salaries"
        decision = guard(sql, analyst)
        assert not decision.allowed
        assert any("salaries" in r for r in decision.reasons)

    def test_subquery_to_a_forbidden_table(self, analyst):
        sql = "SELECT id FROM orders WHERE id IN (SELECT id FROM salaries)"
        assert not guard(sql, analyst).allowed

    def test_unparseable_input_is_refused(self, analyst):
        assert not guard("SELECT FROM WHERE ((", analyst).allowed

    def test_empty_input_is_refused(self, analyst):
        assert not guard("   ", analyst).allowed


class TestReachingOutsideTheEngine:
    @pytest.mark.parametrize("sql", [
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT pg_sleep(10)",
        "SELECT id FROM orders WHERE id = (SELECT pg_sleep(5))",
    ])
    def test_dangerous_functions(self, analyst, sql):
        assert not guard(sql, analyst).allowed

    @pytest.mark.parametrize("sql", [
        "SELECT table_name FROM information_schema.tables",
        "SELECT * FROM pg_catalog.pg_user",
        "SELECT name FROM sqlite_master",
    ])
    def test_system_catalogues(self, analyst, sql):
        decision = guard(sql, analyst)
        assert not decision.allowed
        assert any("system" in r or "not available" in r for r in decision.reasons)


class TestColumnRules:
    def test_denied_column_is_refused(self, analyst):
        decision = guard("SELECT email FROM customers", analyst)
        assert not decision.allowed
        assert any("email" in r for r in decision.reasons)

    def test_permitted_column_on_restricted_table(self, analyst):
        assert guard("SELECT country FROM customers", analyst).allowed

    def test_star_is_refused_when_columns_are_restricted(self, analyst):
        decision = guard("SELECT * FROM customers", analyst)
        assert not decision.allowed
        assert any("name the columns" in r for r in decision.reasons)

    def test_allowlist_excludes_unlisted_column(self, restricted):
        assert not guard("SELECT country, secret_score FROM customers", restricted).allowed

    def test_allowlisted_column_passes(self, restricted):
        assert guard("SELECT id, country FROM customers", restricted).allowed

    def test_qualified_denied_column_is_caught(self, analyst):
        sql = "SELECT c.email FROM customers c JOIN orders o ON o.customer_id = c.id"
        assert not guard(sql, analyst).allowed


class TestRoleScoping:
    def test_table_outside_the_role(self, restricted):
        decision = guard("SELECT id FROM orders", restricted)
        assert not decision.allowed
        assert any("not available to role support" in r for r in decision.reasons)


class TestRegressions:
    """Cases that passed for the wrong reason, or not at all, before being fixed."""

    def test_dangerous_function_is_refused_for_being_dangerous(self, analyst):
        # Previously refused only because the statement read no permitted table,
        # which meant the function check itself was never exercised.
        decision = guard("SELECT id FROM orders WHERE id = (SELECT pg_sleep(5))", analyst)
        assert not decision.allowed
        assert any("pg_sleep" in r for r in decision.reasons)

    def test_alias_does_not_bypass_a_column_rule(self, analyst):
        decision = guard("SELECT c.email FROM customers AS c", analyst)
        assert not decision.allowed
        assert any("customers.email" in r for r in decision.reasons)

    def test_alias_resolution_still_permits_allowed_columns(self, analyst):
        assert guard("SELECT c.country FROM customers AS c", analyst).allowed

    def test_unqualified_column_is_checked_on_a_single_table(self, analyst):
        assert not guard("SELECT email FROM customers", analyst).allowed

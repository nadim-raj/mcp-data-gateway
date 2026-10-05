from mcp_data_gateway.policy import Organisation, TableRule


class TestTableRule:
    def test_open_rule_permits_any_column(self):
        assert TableRule(name="orders").permits_column("total")

    def test_denied_column_is_refused(self):
        rule = TableRule(name="customers", denied_columns=frozenset({"email"}))
        assert not rule.permits_column("email")
        assert rule.permits_column("country")

    def test_allowlist_excludes_everything_else(self):
        rule = TableRule(name="customers", allowed_columns=frozenset({"id"}))
        assert rule.permits_column("id")
        assert not rule.permits_column("country")

    def test_matching_ignores_case(self):
        rule = TableRule(name="customers", denied_columns=frozenset({"Email"}))
        assert not rule.permits_column("EMAIL")

    def test_open_rule_has_no_restrictions(self):
        assert not TableRule(name="orders").has_restrictions
        assert TableRule(name="o", denied_columns=frozenset({"x"})).has_restrictions


class TestRole:
    def test_knows_its_tables(self, analyst):
        assert analyst.permits_table("orders")
        assert not analyst.permits_table("salaries")

    def test_table_lookup_ignores_case(self, analyst):
        assert analyst.permits_table("ORDERS")

    def test_free_sql_is_off_by_default(self, restricted):
        assert not restricted.allow_free_sql


class TestOrganisation:
    def test_member_resolves_to_their_role(self, org):
        assert org.role_for_email("ana@acme.test").name == "analyst"

    def test_email_matching_ignores_case_and_space(self, org):
        assert org.role_for_email("  ANA@acme.test ").name == "analyst"

    def test_unknown_email_gets_nothing(self, org):
        assert org.role_for_email("stranger@elsewhere.test") is None
        assert not org.is_member("stranger@elsewhere.test")

    def test_empty_email_gets_nothing(self, org):
        assert org.role_for_email("") is None

    def test_default_role_applies_only_when_configured(self, analyst):
        without = Organisation(slug="a", issuer="i", audience="a", roles={"analyst": analyst})
        assert without.role_for_email("anyone@a.test") is None
        with_default = Organisation(
            slug="a", issuer="i", audience="a",
            roles={"analyst": analyst}, default_role="analyst",
        )
        assert with_default.role_for_email("anyone@a.test").name == "analyst"

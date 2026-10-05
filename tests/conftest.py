import pytest

from mcp_data_gateway.policy import Organisation, TableRule, build_role


@pytest.fixture
def analyst():
    """A role that may read two tables, with one column withheld."""
    return build_role(
        "analyst",
        [
            TableRule(name="orders"),
            TableRule(name="customers", denied_columns=frozenset({"email", "phone"})),
        ],
        max_rows=100,
        allow_free_sql=True,
    )


@pytest.fixture
def restricted():
    """A role with an explicit column allowlist."""
    return build_role(
        "support",
        [TableRule(name="customers", allowed_columns=frozenset({"id", "country"}))],
        max_rows=50,
    )


@pytest.fixture
def org(analyst, restricted):
    return Organisation(
        slug="acme",
        issuer="https://id.example.com/",
        audience="https://mcp.example.com/",
        roles={"analyst": analyst, "support": restricted},
        members={"ana@acme.test": "analyst", "sam@acme.test": "support"},
    )

"""Unit tests for response field projection."""

from delegation_fabric_core.policy.projection import project_fields


def test_projection_top_level_fields():
    payload = {
        "invoice_id": "INV-042",
        "vendor_id": "V-100",
        "total_minor": 74200000,
        "bank_account": "SECRET_ACC_1234",
    }
    allowed = ["invoice_id", "vendor_id", "total_minor"]
    res = project_fields(payload, allowed)

    assert res.projected == {
        "invoice_id": "INV-042",
        "vendor_id": "V-100",
        "total_minor": 74200000,
    }
    assert res.dropped_count == 1
    assert "bank_account" not in res.projected


def test_projection_nested_fields():
    payload = {
        "vendor": {
            "id": "V-100",
            "name": "ACME Corp",
            "bank_account": "SENSITIVE_123",
        },
        "status": "pending",
    }
    allowed = ["vendor.id", "vendor.name", "status"]
    res = project_fields(payload, allowed)

    assert res.projected == {
        "vendor": {
            "id": "V-100",
            "name": "ACME Corp",
        },
        "status": "pending",
    }
    assert "bank_account" not in res.projected["vendor"]


def test_projection_array_of_objects():
    payload = [
        {"line_no": 1, "description": "Widget A", "unit_price": 100, "internal_margin": 45},
        {"line_no": 2, "description": "Widget B", "unit_price": 200, "internal_margin": 60},
    ]
    allowed = ["line_no", "description", "unit_price"]
    res = project_fields(payload, allowed)

    assert res.projected == [
        {"line_no": 1, "description": "Widget A", "unit_price": 100},
        {"line_no": 2, "description": "Widget B", "unit_price": 200},
    ]
    assert res.dropped_count == 2


def test_projection_empty_allowlist_drops_all():
    payload = {"a": 1, "b": 2}
    res = project_fields(payload, [])
    assert res.projected == {}
    assert res.dropped_count == 2

    res_list = project_fields([1, 2, 3], [])
    assert res_list.projected == []


def test_projection_non_existent_fields_handled():
    payload = {"a": 1}
    res = project_fields(payload, ["b", "c.d"])
    assert res.projected == {}
    assert res.dropped_count == 1

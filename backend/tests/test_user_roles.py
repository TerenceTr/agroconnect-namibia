# ====================================================================
# backend/tests/test_user_roles.py — User Role Helper Tests (PYRIGHT-CLEAN)
# ====================================================================
# FILE ROLE:
#   Unit tests for User role helper @properties:
#     - is_admin / is_farmer / is_customer
#     - role_name mapping
#
# NOTE:
#   We do not need a DB session here—just validate helper behavior.
# ====================================================================

from __future__ import annotations

from backend.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_FARMER, User


def test_role_helpers() -> None:
    """Validate that role helper properties behave correctly."""
    u = User()

    # Admin
    u.role = ROLE_ADMIN
    assert u.is_admin is True
    assert u.is_farmer is False
    assert u.is_customer is False
    assert u.role_name == "admin"

    # Farmer
    u.role = ROLE_FARMER
    assert u.is_admin is False
    assert u.is_farmer is True
    assert u.is_customer is False
    assert u.role_name == "farmer"

    # Customer
    u.role = ROLE_CUSTOMER
    assert u.is_admin is False
    assert u.is_farmer is False
    assert u.is_customer is True
    assert u.role_name == "customer"

# ============================================================================
# backend/services/ussd_service.py — AgroConnect USSD Session Engine
# ----------------------------------------------------------------------------
# FILE ROLE:
#   • Central brain for AgroConnect's USSD experience
#   • Handles Africa's Talking USSD callback inputs and returns valid menus
#   • Reuses the existing core business entities already present in AgroConnect
#  USSD CODE: *384*33840#
# KEY UX FIXES IN THIS VERSION:
#   ✅ Public menus are dynamic:
#      - Before activation: show Register/Activate + Login
#      - After activation: hide Register/Activate and show Login + Reset PIN
#   ✅ Successful registration/activation no longer ends the session
#      immediately; the user is taken straight into the dashboard
#   ✅ View-style actions no longer return END blindly
#      (monthly sales, stock alerts, bank profile, help, payment info)
#      so they no longer feel like the session has expired
#   ✅ Explicit 0 Back / 0 Main Menu behavior is now consistent
#   ✅ Post-action result screens keep the session alive and allow the user
#      to continue instead of forcing a new dial session
#   ✅ Session/log persistence is best-effort only and will not crash menus
#
# ACCOUNT MODEL:
#   ✅ `users` is the universal account table used by web + USSD
#   ✅ `ussd_credentials` stores the USSD PIN / lockout metadata
#   ✅ Existing web users can activate USSD on the same account
#   ✅ New users created in USSD are still normal `users` table records
# ============================================================================

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Optional, cast

from sqlalchemy import bindparam, func, inspect, select, text

from backend.database.db import db
from backend.extensions import bcrypt
from backend.models.cart_item import CartItem
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.payment import Payment
from backend.models.product import Product
from backend.models.user import ROLE_ADMIN, ROLE_FARMER, User
from backend.services.africastalking_service import send_sms_via_africastalking
from backend.services.farmer_commerce_settings import (
    default_farmer_commerce_settings,
    read_farmer_commerce_settings,
)

try:
    from backend.models.user import ROLE_CUSTOMER  # type: ignore
except Exception:
    ROLE_CUSTOMER = 3

logger = logging.getLogger("agroconnect.ussd")

USSD_CONTINUE = "CON"
USSD_END = "END"

USSD_SESSIONS_TABLE = "ussd_sessions"
USSD_ACTIVITY_LOGS_TABLE = "ussd_activity_logs"
USSD_CREDENTIALS_TABLE = "ussd_credentials"

_MEMORY_SESSIONS: dict[str, dict[str, Any]] = {}
_REGISTRATION_RESUME_WINDOW_MINUTES = 120

# Public registration states that are safe to resume after a provider timeout.
# This prevents long create-account journeys from being lost when Africa's
# Talking or the handset drops the live session before completion.
_REGISTRATION_RESUME_STATES: set[str] = {
    "farmer_register_name",
    "farmer_register_email",
    "farmer_register_web_password",
    "farmer_register_web_password_confirm",
    "farmer_register_pin",
    "customer_register_name",
    "customer_register_email",
    "customer_register_web_password",
    "customer_register_web_password_confirm",
    "customer_register_pin",
}


CATEGORY_CHOICES: dict[str, str] = {
    "1": "Fresh Produce",
    "2": "Animal Products",
    "3": "Fish & Seafood",
    "4": "Staples",
    "5": "Nuts, Seeds & Oils",
    "6": "Honey & Sweeteners",
    "7": "Value-Added & Processed",
    "8": "Farm Supplies",
    "9": "Wild Harvest",
}

UNIT_CHOICES: dict[str, str] = {
    "1": "kg",
    "2": "each",
    "3": "l",
    "4": "g",
    "5": "ml",
    "6": "pack",
}

# ---------------------------------------------------------------------------
# USSD-friendly bank choices.
#
# `code` is a short institution code displayed to the farmer.
# `branch_code` remains the EFT / branch code that can be edited separately.
# ---------------------------------------------------------------------------
BANK_PROFILE_BANK_CHOICES: dict[str, dict[str, str]] = {
    "1": {"name": "Bank Windhoek", "code": "BWN"},
    "2": {"name": "FNB Namibia", "code": "FNB"},
    "3": {"name": "Standard Bank Namibia", "code": "SBN"},
    "4": {"name": "Nedbank Namibia", "code": "NBN"},
    "5": {"name": "NamPost Savings Bank", "code": "NPSB"},
    "6": {"name": "Letshego Bank Namibia", "code": "LBN"},
}

STATE_ROOT = "root"

STATE_FARMER_MENU = "farmer_menu"
STATE_FARMER_REGISTER_NAME = "farmer_register_name"
STATE_FARMER_REGISTER_EMAIL = "farmer_register_email"
STATE_FARMER_REGISTER_WEB_PASSWORD = "farmer_register_web_password"
STATE_FARMER_REGISTER_WEB_PASSWORD_CONFIRM = "farmer_register_web_password_confirm"
STATE_FARMER_REGISTER_PIN = "farmer_register_pin"
STATE_FARMER_LOGIN_PIN = "farmer_login_pin"
STATE_FARMER_SECURE_MENU = "farmer_secure_menu"

# Farmer product management states
STATE_FARMER_PRODUCTS_PAGE = "farmer_products_page"
STATE_FARMER_PRODUCT_ACTIONS = "farmer_product_actions"
STATE_FARMER_PRODUCT_VIEW = "farmer_product_view"
STATE_FARMER_PRODUCT_UPDATE_MENU = "farmer_product_update_menu"
STATE_FARMER_PRODUCT_UPDATE_NAME = "farmer_product_update_name"
STATE_FARMER_PRODUCT_UPDATE_DESCRIPTION = "farmer_product_update_description"
STATE_FARMER_PRODUCT_UPDATE_CATEGORY = "farmer_product_update_category"
STATE_FARMER_PRODUCT_UPDATE_PRICE = "farmer_product_update_price"
STATE_FARMER_PRODUCT_UPDATE_QTY = "farmer_product_update_qty"
STATE_FARMER_PRODUCT_UPDATE_UNIT = "farmer_product_update_unit"
STATE_FARMER_PRODUCT_DELETE_CONFIRM = "farmer_product_delete_confirm"
STATE_FARMER_PRODUCT_DEMAND_VIEW = "farmer_product_demand_view"
STATE_FARMER_PRODUCT_REJECTION_VIEW = "farmer_product_rejection_view"
STATE_FARMER_PRODUCT_APPEAL_INPUT = "farmer_product_appeal_input"

# Farmer product creation states
STATE_FARMER_ADD_PRODUCT_NAME = "farmer_add_product_name"
STATE_FARMER_ADD_PRODUCT_DESCRIPTION = "farmer_add_product_description"
STATE_FARMER_ADD_PRODUCT_CATEGORY = "farmer_add_product_category"
STATE_FARMER_ADD_PRODUCT_PRICE = "farmer_add_product_price"
STATE_FARMER_ADD_PRODUCT_QTY = "farmer_add_product_qty"
STATE_FARMER_ADD_PRODUCT_UNIT = "farmer_add_product_unit"

# Farmer order management states
STATE_FARMER_ORDERS_PAGE = "farmer_orders_page"
STATE_FARMER_ORDER_ACTIONS = "farmer_order_actions"
STATE_FARMER_ORDER_PAYMENT_VIEW = "farmer_order_payment_view"
STATE_FARMER_ORDER_DELIVERY_MENU = "farmer_order_delivery_menu"
STATE_FARMER_ORDER_DELIVERY_FEE_INPUT = "farmer_order_delivery_fee_input"
STATE_FARMER_ORDER_READY_FOR_PAYMENT_CONFIRM = "farmer_order_ready_for_payment_confirm"
STATE_FARMER_PAYMENT_CONFIRMATIONS_PAGE = "farmer_payment_confirmations_page"
STATE_FARMER_PAYMENT_CONFIRMATION_ACTIONS = "farmer_payment_confirmation_actions"

# Farmer analytics / info views
STATE_FARMER_MONTHLY_SALES_VIEW = "farmer_monthly_sales_view"
STATE_FARMER_STOCK_ALERTS_VIEW = "farmer_stock_alerts_view"
STATE_FARMER_BANK_PROFILE_VIEW = "farmer_bank_profile_view"
STATE_FARMER_BANK_PROFILE_MENU = "farmer_bank_profile_menu"
STATE_FARMER_BANK_PROFILE_BANK = "farmer_bank_profile_bank"
STATE_FARMER_BANK_PROFILE_ACCOUNT_NAME = "farmer_bank_profile_account_name"
STATE_FARMER_BANK_PROFILE_ACCOUNT_NUMBER = "farmer_bank_profile_account_number"
STATE_FARMER_BANK_PROFILE_BRANCH_CODE = "farmer_bank_profile_branch_code"
STATE_FARMER_BANK_PROFILE_BRANCH_TOWN = "farmer_bank_profile_branch_town"
STATE_FARMER_BANK_PROFILE_PAYMENT_REF = "farmer_bank_profile_payment_ref"
STATE_FARMER_HELP_MENU = "farmer_help_menu"
STATE_FARMER_HELP_VIEW = "farmer_help_view"
STATE_FARMER_RESULT_VIEW = "farmer_result_view"
STATE_FARMER_PRODUCT_SEARCH_INPUT = "farmer_product_search_input"
STATE_FARMER_ORDER_SEARCH_INPUT = "farmer_order_search_input"

STATE_CUSTOMER_MENU = "customer_menu"
STATE_CUSTOMER_REGISTER_NAME = "customer_register_name"
STATE_CUSTOMER_REGISTER_EMAIL = "customer_register_email"
STATE_CUSTOMER_REGISTER_WEB_PASSWORD = "customer_register_web_password"
STATE_CUSTOMER_REGISTER_WEB_PASSWORD_CONFIRM = "customer_register_web_password_confirm"
STATE_CUSTOMER_REGISTER_PIN = "customer_register_pin"
STATE_CUSTOMER_LOGIN_PIN = "customer_login_pin"
STATE_CUSTOMER_SECURE_MENU = "customer_secure_menu"
STATE_CUSTOMER_BROWSE_CATEGORIES = "customer_browse_categories"
STATE_CUSTOMER_PRODUCT_SEARCH_INPUT = "customer_product_search_input"
STATE_CUSTOMER_PRODUCTS_PAGE = "customer_products_page"
STATE_CUSTOMER_PRODUCT_ACTIONS = "customer_product_actions"
STATE_CUSTOMER_PRODUCT_QTY_INPUT = "customer_product_qty_input"
STATE_CUSTOMER_CART_PAGE = "customer_cart_page"
STATE_CUSTOMER_CART_ITEM_ACTIONS = "customer_cart_item_actions"
STATE_CUSTOMER_CART_QTY_INPUT = "customer_cart_qty_input"
STATE_CUSTOMER_CART_REMOVE_CONFIRM = "customer_cart_remove_confirm"
STATE_CUSTOMER_CHECKOUT_DELIVERY_METHOD = "customer_checkout_delivery_method"
STATE_CUSTOMER_CHECKOUT_ADDRESS = "customer_checkout_address"
STATE_CUSTOMER_CHECKOUT_PAYMENT_METHOD = "customer_checkout_payment_method"
STATE_CUSTOMER_CHECKOUT_REVIEW = "customer_checkout_review"
STATE_CUSTOMER_ORDERS_PAGE = "customer_orders_page"
STATE_CUSTOMER_ORDER_DETAIL = "customer_order_detail"
STATE_CUSTOMER_PAYMENT_INFO = "customer_payment_info"
STATE_CUSTOMER_PAYMENT_ORDER_CODE = "customer_payment_order_code"
STATE_CUSTOMER_PAYMENT_REFERENCE_INPUT = "customer_payment_reference_input"
STATE_CUSTOMER_HELP_VIEW = "customer_help_view"
STATE_CUSTOMER_RESULT_VIEW = "customer_result_view"


@dataclass(slots=True)
class UssdResponse:
    prefix: str
    message: str


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        text_value = str(value).strip()
    except Exception:
        return default
    return text_value or default


def _digits_only(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())


def _utcnow() -> datetime:
    return datetime.utcnow()


def _money(value: Any) -> str:
    try:
        amount = Decimal(str(value or 0))
    except Exception:
        amount = Decimal("0")
    return f"N$ {amount.quantize(Decimal('0.01'))}"


def _short_public_code(prefix: str, value: Any) -> str:
    raw = _safe_str(value)
    if not raw:
        return f"{prefix}----"
    compact = raw.replace("-", "").upper()
    return f"{prefix}{compact[:6]}"


def _as_uuid(value: Any) -> Optional[uuid.UUID]:
    """
    Best-effort UUID coercion used throughout long USSD flows.

    WHY THIS HELPER EXISTS:
      • session payloads frequently store IDs as strings
      • ORM attributes may already be uuid.UUID instances
      • malformed IDs must never crash a live USSD session

    Returning None keeps the flow resilient and fixes static-analysis / runtime
    errors where UUID conversion helpers are referenced from multiple states.
    """
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value

    raw = _safe_str(value)
    if not raw:
        return None

    try:
        return uuid.UUID(raw)
    except Exception:
        return None


def _quote_financials(products_subtotal: Any, delivery_fee: Any) -> dict[str, Decimal]:
    """
    Compute the quoted commercial totals used by both farmer and customer views.

    VAT POLICY:
      • VAT is computed at 15% of (products subtotal + delivery fee)
      • all returned values are quantized to 2 decimal places

    The helper centralizes quote math so the same totals appear consistently in:
      • farmer ready-for-payment confirmation
      • customer payment info
      • notifications / SMS summaries
    """
    subtotal = _decimal_or_zero(products_subtotal).quantize(Decimal('0.01'))
    fee = _decimal_or_zero(delivery_fee).quantize(Decimal('0.01'))
    base_total = (subtotal + fee).quantize(Decimal('0.01'))
    vat_amount = (base_total * Decimal('0.15')).quantize(Decimal('0.01'))
    grand_total = (base_total + vat_amount).quantize(Decimal('0.01'))
    return {
        'products_subtotal': subtotal,
        'delivery_fee': fee,
        'vat_amount': vat_amount,
        'grand_total': grand_total,
    }


def _delivery_quote_is_ready(delivery_fee_status: Any) -> bool:
    """
    Return True when the farmer has already quoted the order and the customer
    can proceed to payment.
    """
    normalized = _safe_str(delivery_fee_status).lower().replace(' ', '_')
    return normalized in {
        'awaiting_customer_payment',
        'ready_for_payment',
        'quoted',
        'quote_ready',
        'payment_pending',
        'payment_received',
        'paid',
    }


def _customer_checkout_stage_label(delivery_method: Any, delivery_fee_status: Any) -> str:
    """
    Human-readable quote stage shown to the customer.

    DELIVERY UX:
      • delivery orders wait for the farmer quote first
      • pickup orders are effectively ready once the order is created
      • once quoted, the customer can see totals and submit a payment reference
    """
    method_value = _safe_str(delivery_method).lower()
    if method_value == 'pickup' and not _safe_str(delivery_fee_status):
        return 'Ready for payment'
    if _delivery_quote_is_ready(delivery_fee_status):
        return 'Ready for payment'
    return 'Waiting for farmer quote'


def _farmer_bank_profile_is_complete(farmer_id: str) -> bool:
    """
    Return True when the farmer has enough EFT profile data to quote an EFT
    order confidently from USSD.

    Required fields:
      • bank name
      • account name
      • account number
      • branch code

    Branch town / payment instructions improve the experience but are not hard
    blockers for basic EFT quoting.
    """
    row = _farmer_payment_profile_row(farmer_id)
    if not row:
        return False

    required_values = [
        _safe_str(row.get('bank_name')),
        _safe_str(row.get('account_name')),
        _safe_str(row.get('account_number')),
        _safe_str(row.get('branch_code')),
    ]
    return all(bool(value) for value in required_values)


def _decimal_from_input(value: Any) -> Optional[Decimal]:
    text_value = _safe_str(value).replace(",", ".")
    if not text_value:
        return None
    try:
        amount = Decimal(text_value)
    except (InvalidOperation, ValueError):
        return None
    if amount <= 0:
        return None
    return amount


def _decimal_or_zero(value: Any) -> Decimal:
    """
    Return a concrete Decimal value for arithmetic.

    This helper avoids Optional / None arithmetic paths that static type
    checkers can flag in long USSD menu flows.
    """
    try:
        return Decimal(str(value or 0))
    except Exception:
        return Decimal("0")


def _int_or_zero(value: Any) -> int:
    """
    Return a concrete int value for paging / counters.

    Session dictionaries can contain missing keys or None values. Converting
    through this helper keeps pagination math type-safe and predictable.
    """
    try:
        return int(value or 0)
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Phone normalization policy
# ---------------------------------------------------------------------------
# STORAGE RULES FOR THIS SERVICE:
#   • users.phone                     => local display form (081xxxxxxx)
#   • ussd_credentials.phone_number   => E.164 provider form (+26481xxxxxxx)
#   • ussd_sessions / activity logs   => E.164 provider form (+26481xxxxxxx)
#
# WHY THIS SPLIT EXISTS:
#   • web/admin screens should show familiar local Namibia numbers
#   • Africa's Talking and SMS/USSD channel records work best with E.164
#   • lookups must still succeed even if legacy rows exist in mixed formats
# ---------------------------------------------------------------------------
def phone_to_local(value: Any) -> str:
    raw = _safe_str(value)
    if not raw:
        return ""

    digits = _digits_only(raw)
    if not digits:
        return ""

    if len(digits) == 10 and digits.startswith(("081", "083", "085")):
        return digits
    if len(digits) == 12 and digits.startswith(("26481", "26483", "26485")):
        return f"0{digits[3:]}"
    if digits.startswith("264") and len(digits) > 3:
        return f"0{digits[3:]}"
    return digits if digits.startswith("0") else ""


# Backward-compatible alias retained because the rest of the USSD engine
# already calls `normalize_phone_number(...)` for channel-facing values.
def normalize_phone_number(value: Any) -> str:
    local = phone_to_local(value)
    if local:
        return f"+264{local[1:]}"

    raw = _safe_str(value)
    if not raw:
        return ""

    digits = _digits_only(raw)
    if not digits:
        return ""
    return f"+{digits}" if raw.startswith("+") or digits.startswith("264") else f"+{digits}"


def phone_to_key(value: Any) -> str:
    return _digits_only(normalize_phone_number(value))


def _phone_candidates(phone_number: Any) -> list[str]:
    e164 = normalize_phone_number(phone_number)
    local = phone_to_local(phone_number)
    key = phone_to_key(phone_number)
    candidates: list[str] = []

    def add(value: Any) -> None:
        v = _safe_str(value)
        if v and v not in candidates:
            candidates.append(v)

    add(phone_number)
    add(local)
    add(e164)
    add(key)
    if key:
        add(f"+{key}")
        if key.startswith("264"):
            add(f"0{key[3:]}")

    return candidates


def _engine_scalar_exists(sql_text: str, params: Optional[dict[str, Any]] = None) -> bool:
    try:
        with db.engine.connect() as conn:
            row = conn.execute(text(sql_text), params or {}).first()
            return row is not None
    except Exception:
        return False


def _table_exists(table_name: str) -> bool:
    name = _safe_str(table_name)
    if not name:
        return False

    try:
        inspector = inspect(db.engine)
        if inspector.has_table(name):
            return True
        if inspector.has_table(name, schema="public"):
            return True
    except Exception:
        pass

    if _engine_scalar_exists(
        """
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = :table_name
        LIMIT 1
        """,
        {"table_name": name},
    ):
        return True

    return False


_USERS_COLUMN_CACHE: dict[str, Optional[bool]] = {
    "last_login_at": None,
    "last_seen_at": None,
}


def _users_table_has_column(column_name: str) -> bool:
    cached = _USERS_COLUMN_CACHE.get(column_name)
    if isinstance(cached, bool):
        return cached

    try:
        columns = inspect(db.engine).get_columns("users")
        ok = any((column.get("name") == column_name) for column in (columns or []))
    except Exception:
        ok = False

    _USERS_COLUMN_CACHE[column_name] = ok
    return ok


def _touch_user_auth_timestamps(*, user_id: Any, update_login: bool = False) -> None:
    """
    Best-effort timestamp update for DB columns that may exist even when the
    ORM model does not explicitly map them.

    This keeps the USSD flow aligned with your `users` table screenshots and
    SQL dump, where `last_login_at` and `last_seen_at` are present.
    """
    try:
        user_uuid = uuid.UUID(str(user_id))
    except Exception:
        return

    now = _utcnow()
    try:
        with db.engine.begin() as conn:
            if _users_table_has_column("last_seen_at"):
                conn.execute(
                    text("UPDATE public.users SET last_seen_at = :ts WHERE id = :uid"),
                    {"ts": now, "uid": str(user_uuid)},
                )
            if update_login and _users_table_has_column("last_login_at"):
                conn.execute(
                    text("UPDATE public.users SET last_login_at = :ts WHERE id = :uid"),
                    {"ts": now, "uid": str(user_uuid)},
                )
    except Exception:
        # Never break the USSD journey because convenience timestamp fields failed.
        return


def _resume_cutoff_timestamp() -> datetime:
    from datetime import timedelta

    return _utcnow() - timedelta(minutes=_REGISTRATION_RESUME_WINDOW_MINUTES)


def _phone_has_completed_ussd_account(phone_number: Any) -> bool:
    """
    Return True when this phone already has a completed USSD-capable account.

    This guard prevents stale registration drafts from hijacking a fresh dial
    after the user has already finished activation or can already log in.
    """
    normalized_phone = normalize_phone_number(phone_number)
    if not normalized_phone:
        return False

    if _has_ussd_pin_for_phone(normalized_phone):
        return True

    existing_user = _find_user_by_phone(normalized_phone)
    return existing_user is not None


def _clear_registration_drafts_for_phone(phone_number: Any, service_code: Any = "") -> None:
    """
    Remove stale public registration drafts for this phone number.

    Why this matters:
      • each USSD step is stored under the provider session id
      • after successful activation, older incomplete drafts may still exist
      • a later fresh dial could resume one of those old drafts unless we clear
        them explicitly
    """
    normalized_phone = normalize_phone_number(phone_number)
    normalized_service_code = _safe_str(service_code)
    if not normalized_phone:
        return

    if _table_exists(USSD_SESSIONS_TABLE):
        try:
            db.session.execute(
                text(
                    f"""
                    UPDATE public.{USSD_SESSIONS_TABLE}
                    SET ended_at = COALESCE(ended_at, :ended_at),
                        updated_at = :updated_at
                    WHERE phone_number = :phone_number
                      AND state IN :registration_states
                      AND (
                            :service_code = ''
                            OR COALESCE(service_code, '') = :service_code
                      )
                    """
                ).bindparams(bindparam("registration_states", expanding=True)),
                {
                    "ended_at": _utcnow(),
                    "updated_at": _utcnow(),
                    "phone_number": normalized_phone,
                    "registration_states": sorted(_REGISTRATION_RESUME_STATES),
                    "service_code": normalized_service_code,
                },
            )
            db.session.commit()
        except Exception:
            db.session.rollback()

    for sid, payload in list(_MEMORY_SESSIONS.items()):
        if normalize_phone_number(payload.get("phone_number")) != normalized_phone:
            continue
        if _safe_str(payload.get("state")) not in _REGISTRATION_RESUME_STATES:
            continue
        row_service_code = _safe_str(payload.get("service_code"))
        if normalized_service_code and row_service_code and row_service_code != normalized_service_code:
            continue
        _MEMORY_SESSIONS.pop(sid, None)


def _recent_registration_session_for_phone(phone_number: Any, service_code: Any = "") -> Optional[dict[str, Any]]:
    """
    Return the most recent unfinished public registration draft for this phone.

    This is the main protection against the provider message "This session has
    expired" during long registration flows. When the user redials, we restore
    the last safe registration step instead of forcing them to start again.
    """
    normalized_phone = normalize_phone_number(phone_number)
    normalized_service_code = _safe_str(service_code)

    # Prefer persisted DB-backed session drafts when the table exists.
    if _table_exists(USSD_SESSIONS_TABLE):
        try:
            rows = db.session.execute(
                text(
                    f"""
                    SELECT session_id, phone_number, service_code, state, data_json,
                           is_authenticated, user_id, started_at, updated_at
                    FROM public.{USSD_SESSIONS_TABLE}
                    WHERE phone_number = :phone_number
                      AND COALESCE(is_authenticated, false) = false
                      AND COALESCE(updated_at, started_at, NOW()) >= :resume_cutoff
                    ORDER BY updated_at DESC NULLS LAST, started_at DESC NULLS LAST
                    LIMIT 10
                    """
                ),
                {
                    "phone_number": normalized_phone,
                    "resume_cutoff": _resume_cutoff_timestamp(),
                },
            ).mappings().all()

            for raw in rows or []:
                state_value = _safe_str(raw.get("state"))
                if state_value not in _REGISTRATION_RESUME_STATES:
                    continue

                row_service_code = _safe_str(raw.get("service_code"))
                if normalized_service_code and row_service_code and row_service_code != normalized_service_code:
                    continue

                payload = dict(raw)
                data_json = payload.get("data_json") or {}
                return {
                    "session_id": _safe_str(payload.get("session_id")),
                    "phone_number": normalize_phone_number(payload.get("phone_number") or normalized_phone),
                    "service_code": row_service_code or normalized_service_code,
                    "state": state_value,
                    "data": data_json if isinstance(data_json, dict) else {},
                    "is_authenticated": False,
                    "user_id": None,
                    "started_at": _safe_str(payload.get("started_at")),
                    "updated_at": _safe_str(payload.get("updated_at")),
                }
        except Exception:
            db.session.rollback()

    # Fallback to in-memory drafts when DB session storage is unavailable.
    for payload in sorted(_MEMORY_SESSIONS.values(), key=lambda item: _safe_str(item.get("updated_at")), reverse=True):
        if normalize_phone_number(payload.get("phone_number")) != normalized_phone:
            continue
        if bool(payload.get("is_authenticated")):
            continue
        state_value = _safe_str(payload.get("state"))
        if state_value not in _REGISTRATION_RESUME_STATES:
            continue
        row_service_code = _safe_str(payload.get("service_code"))
        if normalized_service_code and row_service_code and row_service_code != normalized_service_code:
            continue
        return deepcopy(payload)

    return None


def _maybe_resume_registration(session: dict[str, Any], current_text: str) -> None:
    """
    Restore an unfinished registration only when a brand-new dial starts.

    Safety guards:
      • never resume once the phone already has a completed USSD-capable account
      • never resume a stale draft older than the configured resume window
      • only resume when the incoming callback starts a brand-new dial
    """
    if _safe_str(current_text):
        return
    if _safe_str(session.get("state"), STATE_ROOT) != STATE_ROOT:
        return
    if bool(session.get("is_authenticated")):
        return

    phone_number = session.get("phone_number")
    service_code = session.get("service_code")

    if _phone_has_completed_ussd_account(phone_number):
        _clear_registration_drafts_for_phone(phone_number, service_code)
        return

    draft = _recent_registration_session_for_phone(phone_number, service_code)
    if not draft:
        return

    session["state"] = _safe_str(draft.get("state"), STATE_ROOT)
    session["data"] = cast(dict[str, Any], draft.get("data") or {})


def _hash_secret(secret: str) -> str:
    hashed = bcrypt.generate_password_hash(secret)
    if isinstance(hashed, bytes):
        return hashed.decode("utf-8", errors="ignore")
    return str(hashed)


def _check_secret(secret_hash: str, secret: str) -> bool:
    try:
        return bool(bcrypt.check_password_hash(secret_hash, secret))
    except Exception:
        return False


def _pin_is_valid(pin: str) -> bool:
    return pin.isdigit() and len(pin) == 4


def _normalize_email(value: Any) -> str:
    """Return a lowercase email-like value suitable for DB storage."""
    return _safe_str(value).strip().lower()


def _email_is_valid(value: Any) -> bool:
    email = _normalize_email(value)
    return bool(email and "@" in email and "." in email)


def _web_password_validation_error(password: Any) -> str:
    """
    Validate a USSD-captured web password.

    WHY THIS IS STRICTER THAN WEB:
      • Africa's Talking sends the full USSD journey in the `text` field.
      • Very long or delimiter-like values make that payload grow quickly.
      • `*` and `#` are especially risky in USSD journeys.

    To keep registration stable, USSD only accepts a short, USSD-safe subset.
    Users can still change their password later from the web interface.
    """
    raw = _safe_str(password)
    if len(raw) < 6:
        return "Password must be 6-12 chars"
    if len(raw) > 12:
        return "Password must be 6-12 chars"
    if any(ch.isspace() for ch in raw):
        return "No spaces allowed in password"
    if "*" in raw or "#" in raw:
        return "Do not use * or # in password"
    if not re.fullmatch(r"[A-Za-z0-9._@!-]+", raw):
        return "Use letters, numbers, . _ @ ! - only"
    return ""


def _web_password_is_valid(password: Any) -> bool:
    return _web_password_validation_error(password) == ""


def _registration_password_prompt() -> str:
    return "Set web password\n6-12 chars, no * or #"


def _random_web_password() -> str:
    return f"ussd-web-{uuid.uuid4().hex}"


def _placeholder_email(phone_number: str) -> str:
    base = _digits_only(phone_number) or uuid.uuid4().hex[:12]
    return f"ussd.{base}@agroconnect.local"


def _role_name(role_value: int) -> str:
    if int(role_value) == int(ROLE_FARMER):
        return "farmer"
    if int(role_value) == int(ROLE_CUSTOMER):
        return "customer"
    return "user"


def _first_name(user: User) -> str:
    full_name = _safe_str(getattr(user, "full_name", ""), "User")
    parts = full_name.split()
    return parts[0] if parts else "User"


def _short_text(value: Any, limit: int = 18, default: str = "-") -> str:
    text_value = _safe_str(value, default)
    return text_value if len(text_value) <= limit else f"{text_value[: max(0, limit - 1)]}…"


def _date_label(value: Any) -> str:
    if isinstance(value, datetime):
        return value.strftime("%d/%m")
    return "--/--"


def _date_time_label(value: Any) -> str:
    if isinstance(value, datetime):
        return value.strftime("%d/%m %H:%M")
    return "-"


def _product_status_short(status: Any) -> str:
    raw = _safe_str(status).lower()
    mapping = {
        "pending": "pend",
        "available": "live",
        "approved": "live",
        "published": "live",
        "rejected": "rej",
        "deleted": "del",
    }
    return mapping.get(raw, _short_text(raw or "new", 4, "new"))


def _delivery_status_label(status: Any) -> str:
    raw = _safe_str(status).replace("_", " ").strip()
    return raw.title() if raw else "Pending"


def _is_next_command(value: Any) -> bool:
    return _safe_str(value).lower() in {"n", "next"}


def _is_prev_command(value: Any) -> bool:
    return _safe_str(value).lower() in {"p", "prev"}


def _is_search_command(value: Any) -> bool:
    return _safe_str(value).lower() in {"s", "search"}


def _is_clear_command(value: Any) -> bool:
    return _safe_str(value).lower() in {"c", "clear"}


# ---------------------------------------------------------------------------
# USSD response helpers
# ---------------------------------------------------------------------------
def ussd_continue(message: str) -> UssdResponse:
    return UssdResponse(prefix=USSD_CONTINUE, message=message)


def ussd_end(message: str) -> UssdResponse:
    return UssdResponse(prefix=USSD_END, message=message)


def render_ussd_body(response: UssdResponse) -> str:
    return f"{response.prefix} {response.message}".strip()


# ---------------------------------------------------------------------------
# Session persistence
# ---------------------------------------------------------------------------
def _default_session(session_id: str, phone_number: str, service_code: str) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "phone_number": normalize_phone_number(phone_number),
        "service_code": _safe_str(service_code),
        "state": STATE_ROOT,
        "data": {},
        "last_text": "",
        "is_authenticated": False,
        "user_id": None,
        "started_at": _utcnow().isoformat(),
        "updated_at": _utcnow().isoformat(),
    }


def _load_session(session_id: str, phone_number: str, service_code: str) -> dict[str, Any]:
    default_session = _default_session(session_id, phone_number, service_code)

    if _table_exists(USSD_SESSIONS_TABLE):
        try:
            row = db.session.execute(
                text(
                    f"""
                    SELECT session_id, phone_number, service_code, state,
                           data_json, is_authenticated, user_id,
                           started_at, updated_at, ended_at
                    FROM public.{USSD_SESSIONS_TABLE}
                    WHERE session_id = :session_id
                    """
                ),
                {"session_id": session_id},
            ).mappings().first()

            if row:
                payload = dict(row)
                data_json = payload.get("data_json") or {}
                return {
                    "session_id": _safe_str(payload.get("session_id"), session_id),
                    "phone_number": normalize_phone_number(payload.get("phone_number") or phone_number),
                    "service_code": _safe_str(payload.get("service_code"), service_code),
                    "state": _safe_str(payload.get("state"), STATE_ROOT),
                    "data": data_json if isinstance(data_json, dict) else {},
                    "last_text": _safe_str((data_json or {}).get("last_text")),
                    "is_authenticated": bool(payload.get("is_authenticated")),
                    "user_id": _safe_str(payload.get("user_id")) or None,
                    "started_at": _safe_str(payload.get("started_at"), default_session["started_at"]),
                    "updated_at": _safe_str(payload.get("updated_at"), default_session["updated_at"]),
                }
        except Exception as exc:
            db.session.rollback()
            logger.warning("[USSD] Failed to load DB session, falling back to memory: %s", exc)

    existing = _MEMORY_SESSIONS.get(session_id)
    if existing:
        return deepcopy(existing)
    return default_session


def _save_session(session: dict[str, Any]) -> None:
    session["updated_at"] = _utcnow().isoformat()
    data = dict(session.get("data") or {})
    data["last_text"] = _safe_str(session.get("last_text"))

    if _table_exists(USSD_SESSIONS_TABLE):
        try:
            db.session.execute(
                text(
                    f"""
                    INSERT INTO public.{USSD_SESSIONS_TABLE} (
                        session_id,
                        phone_number,
                        service_code,
                        state,
                        data_json,
                        is_authenticated,
                        user_id,
                        started_at,
                        updated_at
                    ) VALUES (
                        :session_id,
                        :phone_number,
                        :service_code,
                        :state,
                        CAST(:data_json AS jsonb),
                        :is_authenticated,
                        CAST(:user_id AS uuid),
                        :started_at,
                        :updated_at
                    )
                    ON CONFLICT (session_id)
                    DO UPDATE SET
                        phone_number = EXCLUDED.phone_number,
                        service_code = EXCLUDED.service_code,
                        state = EXCLUDED.state,
                        data_json = EXCLUDED.data_json,
                        is_authenticated = EXCLUDED.is_authenticated,
                        user_id = EXCLUDED.user_id,
                        updated_at = EXCLUDED.updated_at
                    """
                ),
                {
                    "session_id": _safe_str(session.get("session_id")),
                    "phone_number": normalize_phone_number(session.get("phone_number")),
                    "service_code": _safe_str(session.get("service_code")),
                    "state": _safe_str(session.get("state"), STATE_ROOT),
                    "data_json": json.dumps(data, ensure_ascii=False),
                    "is_authenticated": bool(session.get("is_authenticated")),
                    "user_id": _safe_str(session.get("user_id")) or None,
                    "started_at": session.get("started_at"),
                    "updated_at": session.get("updated_at"),
                },
            )
            db.session.commit()
            return
        except Exception as exc:
            db.session.rollback()
            logger.warning("[USSD] Failed to save DB session, falling back to memory: %s", exc)

    _MEMORY_SESSIONS[_safe_str(session.get("session_id"))] = deepcopy(session)


def _close_session(session_id: str) -> None:
    if _table_exists(USSD_SESSIONS_TABLE):
        try:
            db.session.execute(
                text(
                    f"UPDATE public.{USSD_SESSIONS_TABLE} "
                    f"SET ended_at = :ended_at WHERE session_id = :session_id"
                ),
                {"session_id": session_id, "ended_at": _utcnow()},
            )
            db.session.commit()
        except Exception:
            db.session.rollback()

    _MEMORY_SESSIONS.pop(session_id, None)


def _log_activity(
    *,
    session: dict[str, Any],
    event_type: str,
    user_input: str = "",
    message_text: str = "",
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    payload = {
        "event_type": event_type,
        "state": _safe_str(session.get("state")),
        "session_id": _safe_str(session.get("session_id")),
        "phone": normalize_phone_number(session.get("phone_number")),
        "user_id": _safe_str(session.get("user_id")) or None,
        "user_input": _safe_str(user_input),
        "message_text": _safe_str(message_text),
        "metadata": metadata or {},
    }

    if _table_exists(USSD_ACTIVITY_LOGS_TABLE):
        try:
            db.session.execute(
                text(
                    f"""
                    INSERT INTO public.{USSD_ACTIVITY_LOGS_TABLE} (
                        session_id,
                        phone_number,
                        event_type,
                        state,
                        user_input,
                        message_text,
                        user_id,
                        metadata_json,
                        created_at
                    ) VALUES (
                        :session_id,
                        :phone_number,
                        :event_type,
                        :state,
                        :user_input,
                        :message_text,
                        CAST(:user_id AS uuid),
                        CAST(:metadata_json AS jsonb),
                        :created_at
                    )
                    """
                ),
                {
                    "session_id": payload["session_id"],
                    "phone_number": payload["phone"],
                    "event_type": payload["event_type"],
                    "state": payload["state"],
                    "user_input": payload["user_input"],
                    "message_text": payload["message_text"],
                    "user_id": payload["user_id"],
                    "metadata_json": json.dumps(payload["metadata"], ensure_ascii=False),
                    "created_at": _utcnow(),
                },
            )
            db.session.commit()
            return
        except Exception as exc:
            db.session.rollback()
            logger.warning("[USSD] Failed to write activity log row: %s", exc)

    logger.info("[USSD][%s] %s", event_type.upper(), payload)


def _persist_runtime_state_and_logs(*, session: dict[str, Any], response: UssdResponse, new_input: str) -> None:
    try:
        _save_session(session)
    except Exception as exc:
        logger.warning("[USSD] Non-critical session persistence failed: %s", exc)
    try:
        _log_activity(
            session=session,
            event_type="callback",
            user_input=new_input,
            message_text=response.message,
            metadata={"prefix": response.prefix},
        )
    except Exception as exc:
        logger.warning("[USSD] Non-critical activity logging failed: %s", exc)


def _extract_new_input(previous_text: str, current_text: str) -> str:
    prev = _safe_str(previous_text)
    curr = _safe_str(current_text)
    if not curr:
        return ""
    if not prev:
        return _safe_str(curr.split("*")[-1])
    if curr == prev:
        return ""
    prefix = f"{prev}*"
    if curr.startswith(prefix):
        return _safe_str(curr[len(prefix):])
    return _safe_str(curr.split("*")[-1])


# ---------------------------------------------------------------------------
# User / credential helpers
# ---------------------------------------------------------------------------
def _find_user_by_phone(phone_number: str, *, role: Optional[int] = None) -> Optional[User]:
    candidates = _phone_candidates(phone_number)
    if not candidates:
        return None

    stmt = select(User).where(User.phone.in_(candidates)).where(User.is_active.is_(True))
    if role is not None:
        stmt = stmt.where(User.role == role)
    return db.session.execute(stmt.limit(1)).scalar_one_or_none()


def _ensure_unique_placeholder_email(phone_number: str) -> str:
    base_email = _placeholder_email(phone_number)
    existing = db.session.execute(select(User).where(User.email == base_email)).scalar_one_or_none()
    if existing is None:
        return base_email
    return f"ussd.{_digits_only(phone_number)}.{uuid.uuid4().hex[:6]}@agroconnect.local"


def _credentials_table_ready() -> bool:
    return _table_exists(USSD_CREDENTIALS_TABLE)


def _load_ussd_credential_row(phone_number: str) -> Optional[dict[str, Any]]:
    if not _credentials_table_ready():
        return None

    candidates = _phone_candidates(phone_number)
    if not candidates:
        return None

    try:
        row = db.session.execute(
            text(
                f"""
                SELECT user_id, phone_number, pin_hash, is_active,
                       failed_attempt_count, locked_until
                FROM public.{USSD_CREDENTIALS_TABLE}
                WHERE phone_number IN :phone_candidates
                ORDER BY
                    CASE WHEN phone_number = :preferred_phone THEN 0 ELSE 1 END,
                    updated_at DESC NULLS LAST,
                    created_at DESC NULLS LAST
                LIMIT 1
                """
            ).bindparams(bindparam("phone_candidates", expanding=True)),
            {
                "phone_candidates": candidates,
                "preferred_phone": normalize_phone_number(phone_number),
            },
        ).mappings().first()
        return dict(row) if row else None
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to read credential row: %s", exc)
        return None


def _has_ussd_pin_for_phone(phone_number: str) -> bool:
    return _load_ussd_credential_row(phone_number) is not None


def _public_farmer_menu(phone_number: str) -> str:
    existing_farmer = _find_user_by_phone(phone_number, role=ROLE_FARMER)
    if existing_farmer is not None and _has_ussd_pin_for_phone(phone_number):
        return "Farmer Menu\n1 Login\n2 Reset PIN\n3 Help\n0 Back"
    return "Farmer Menu\n1 Register / Activate USSD\n2 Login\n3 Help\n0 Back"


def _public_customer_menu(phone_number: str) -> str:
    existing_customer = _find_user_by_phone(phone_number, role=ROLE_CUSTOMER)
    if existing_customer is not None and _has_ussd_pin_for_phone(phone_number):
        return "Customer Menu\n1 Login\n2 Reset PIN\n3 Help\n0 Back"
    return "Customer Menu\n1 Register / Activate USSD\n2 Login\n3 Help\n0 Back"


def _upsert_ussd_pin(user_id: str, phone_number: str, pin: str) -> tuple[bool, str]:
    if not _credentials_table_ready():
        return False, "USSD credentials table is missing. Run the USSD SQL patch first."

    normalized_phone = normalize_phone_number(phone_number)
    pin_hash = _hash_secret(pin)

    try:
        updated = db.session.execute(
            text(
                f"""
                UPDATE public.{USSD_CREDENTIALS_TABLE}
                SET phone_number = :phone_number,
                    pin_hash = :pin_hash,
                    is_active = true,
                    failed_attempt_count = 0,
                    locked_until = NULL,
                    updated_at = :updated_at
                WHERE user_id = CAST(:user_id AS uuid)
                   OR phone_number = :phone_number
                """
            ),
            {
                "user_id": user_id,
                "phone_number": normalized_phone,
                "pin_hash": pin_hash,
                "updated_at": _utcnow(),
            },
        )

        if int(updated.rowcount or 0) > 0:
            db.session.commit()
            return True, "USSD PIN saved successfully."

        db.session.execute(
            text(
                f"""
                INSERT INTO public.{USSD_CREDENTIALS_TABLE} (
                    user_id,
                    phone_number,
                    pin_hash,
                    is_active,
                    created_at,
                    updated_at,
                    failed_attempt_count,
                    locked_until,
                    preferred_language
                ) VALUES (
                    CAST(:user_id AS uuid),
                    :phone_number,
                    :pin_hash,
                    true,
                    :created_at,
                    :updated_at,
                    0,
                    NULL,
                    'en'
                )
                """
            ),
            {
                "user_id": user_id,
                "phone_number": normalized_phone,
                "pin_hash": pin_hash,
                "created_at": _utcnow(),
                "updated_at": _utcnow(),
            },
        )
        db.session.commit()
        return True, "USSD PIN saved successfully."
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to upsert PIN: %s", exc)
        return False, "Could not save USSD PIN."


def _verify_ussd_pin(phone_number: str, pin: str) -> tuple[bool, Optional[str], str]:
    if not _credentials_table_ready():
        return False, None, "USSD credentials table is missing. Run the USSD SQL patch first."

    try:
        row = _load_ussd_credential_row(phone_number)
        if not row:
            return False, None, "No USSD PIN found for this number. Use Register / Activate USSD first."

        if not bool(row.get("is_active")):
            return False, None, "USSD access is inactive for this number."

        locked_until = row.get("locked_until")
        if locked_until and isinstance(locked_until, datetime) and locked_until > _utcnow():
            return False, None, "PIN access is temporarily locked. Try again later."

        matched_phone = normalize_phone_number(row.get("phone_number") or phone_number)
        update_candidates = _phone_candidates(matched_phone)
        pin_hash = _safe_str(row.get("pin_hash"))
        if not pin_hash or not _check_secret(pin_hash, pin):
            db.session.execute(
                text(
                    f"""
                    UPDATE public.{USSD_CREDENTIALS_TABLE}
                    SET failed_attempt_count = COALESCE(failed_attempt_count, 0) + 1,
                        updated_at = :updated_at
                    WHERE phone_number IN :phone_candidates
                    """
                ).bindparams(bindparam("phone_candidates", expanding=True)),
                {"phone_candidates": update_candidates, "updated_at": _utcnow()},
            )
            db.session.commit()
            return False, None, "Invalid PIN."

        db.session.execute(
            text(
                f"""
                UPDATE public.{USSD_CREDENTIALS_TABLE}
                SET failed_attempt_count = 0,
                    last_login_at = :last_login_at,
                    updated_at = :updated_at
                WHERE phone_number IN :phone_candidates
                """
            ).bindparams(bindparam("phone_candidates", expanding=True)),
            {
                "phone_candidates": update_candidates,
                "last_login_at": _utcnow(),
                "updated_at": _utcnow(),
            },
        )
        db.session.commit()
        return True, _safe_str(row.get("user_id")) or None, "PIN verified."
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] PIN verification failed: %s", exc)
        return False, None, "Could not verify PIN."


def activate_or_register_ussd_user(
    *,
    phone_number: str,
    role_value: int,
    full_name: str = "",
    email: str = "",
    web_password: str = "",
    pin: str,
) -> tuple[bool, Optional[User], str]:
    """
    Register a brand-new web + USSD account, or activate USSD on an existing
    same-phone account.

    NEW ACCOUNT FLOW
      • full name
      • email
      • web password
      • USSD PIN

    EXISTING ACCOUNT FLOW
      • keep existing web credentials
      • only activate / reset the USSD PIN

    The helper also updates `users.last_login_at` and `users.last_seen_at`
    best-effort when those DB columns exist.
    """
    normalized_phone = normalize_phone_number(phone_number)
    local_user_phone = phone_to_local(phone_number)
    normalized_email = _normalize_email(email)
    existing_user = _find_user_by_phone(normalized_phone)

    if existing_user is not None:
        existing_role = int(getattr(existing_user, "role", 0) or 0)
        if existing_role != int(role_value):
            return False, None, f"This phone number already belongs to a {_role_name(existing_role)} account."

        changed = False

        # Keep the universal user account on the local Namibia display form.
        current_phone = _safe_str(getattr(existing_user, "phone", ""))
        if local_user_phone and current_phone != local_user_phone:
            setattr(existing_user, "phone", local_user_phone[:20])
            changed = True

        if full_name:
            current_name = _safe_str(getattr(existing_user, "full_name", ""))
            if not current_name or current_name.startswith("USSD User "):
                setattr(existing_user, "full_name", full_name[:200])
                changed = True

        if normalized_email:
            duplicate = db.session.execute(
                select(User).where(User.email == normalized_email).where(User.id != getattr(existing_user, "id"))
            ).scalar_one_or_none()
            if duplicate is not None:
                return False, None, "Email address is already registered."

            current_email = _normalize_email(getattr(existing_user, "email", ""))
            if normalized_email != current_email:
                setattr(existing_user, "email", normalized_email[:200])
                changed = True

        if web_password:
            setattr(existing_user, "password_hash", _hash_secret(web_password))
            changed = True

        if changed:
            try:
                db.session.add(existing_user)
                db.session.commit()
                db.session.refresh(existing_user)
            except Exception as exc:
                db.session.rollback()
                logger.exception("[USSD] Failed to update existing user during activation: %s", exc)
                return False, None, "Could not update account details."

        ok, message = _upsert_ussd_pin(str(getattr(existing_user, "id")), normalized_phone, pin)
        if not ok:
            return False, None, message

        _touch_user_auth_timestamps(user_id=getattr(existing_user, "id"), update_login=True)
        return True, existing_user, "USSD access updated successfully."

    if not normalized_email:
        return False, None, "Email is required."
    if not _email_is_valid(normalized_email):
        return False, None, "Valid email is required."
    if not web_password:
        return False, None, "Web password is required."

    duplicate_email = db.session.execute(select(User).where(User.email == normalized_email)).scalar_one_or_none()
    if duplicate_email is not None:
        return False, None, "Email address is already registered."

    try:
        user = User()
        display_phone = local_user_phone or normalized_phone
        user.full_name = full_name[:200] if full_name else f"USSD User {display_phone}"
        # UNIVERSAL ACCOUNT RULE:
        #   `users.phone` must stay in local display form such as 081..., while
        #   `ussd_credentials.phone_number` keeps the +264... provider form.
        user.phone = display_phone
        user.email = normalized_email[:200]
        user.location = None
        user.password_hash = _hash_secret(web_password)
        user.role = int(role_value)
        user.is_active = True

        db.session.add(user)
        db.session.commit()
        db.session.refresh(user)

        ok, message = _upsert_ussd_pin(str(getattr(user, "id")), normalized_phone, pin)
        if not ok:
            return False, None, message

        _touch_user_auth_timestamps(user_id=getattr(user, "id"), update_login=True)
        return True, user, f"{_role_name(role_value).capitalize()} registered successfully."
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Hybrid registration/activation failed: %s", exc)
        return False, None, "Registration failed. Please try again."


# ---------------------------------------------------------------------------
# Farmer settings / profile helpers
# ---------------------------------------------------------------------------
def _farmer_settings(farmer_id: str) -> dict[str, Any]:
    try:
        return read_farmer_commerce_settings(farmer_id)
    except Exception:
        return default_farmer_commerce_settings()


def _farmer_orders_sms_enabled(farmer_id: str) -> bool:
    settings = _farmer_settings(farmer_id)
    notifications = cast(dict[str, Any], settings.get("notifications") or {})
    return bool(notifications.get("orders_sms", False))


def _farmer_low_stock_threshold(farmer_id: str) -> int:
    settings = _farmer_settings(farmer_id)
    analytics = cast(dict[str, Any], settings.get("analytics") or {})
    try:
        return max(0, int(analytics.get("custom_low_stock_threshold", 5) or 5))
    except Exception:
        return 5


# ---------------------------------------------------------------------------
# Farmer business helpers
# ---------------------------------------------------------------------------
def create_product_for_farmer(
    *,
    farmer: User,
    product_name: str,
    description: str,
    category: str,
    price: Decimal,
    quantity: Decimal,
    unit: str,
) -> tuple[bool, str, Optional[uuid.UUID]]:
    try:
        product = Product()
        product.user_id = getattr(farmer, "id")
        product.product_name = product_name
        product.description = (
            description[:500]
            if _safe_str(description)
            else f"Added via USSD on {_utcnow().strftime('%Y-%m-%d %H:%M')}"
        )
        product.category = category
        product.price = price
        product.quantity = quantity
        product.unit = unit
        product.status = "pending"
        product.image_url = "/Assets/product_images/default.jpg"

        if hasattr(product, "submitted_at"):
            setattr(product, "submitted_at", _utcnow())
        if hasattr(product, "status_updated_at"):
            setattr(product, "status_updated_at", _utcnow())
        if hasattr(product, "last_edited_by"):
            setattr(product, "last_edited_by", getattr(farmer, "id", None))
        if hasattr(product, "last_edited_at"):
            setattr(product, "last_edited_at", _utcnow())

        db.session.add(product)
        db.session.commit()
        db.session.refresh(product)
        return True, "Product added and sent for admin review.", getattr(product, "product_id", None)
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Product creation failed: %s", exc)
        return False, "Could not add product. Please try again.", None


def farmer_latest_orders(
    farmer_id: str,
    *,
    limit: int = 3,
    offset: int = 0,
    search_term: str = "",
) -> list[dict[str, Any]]:
    """
    Return recent farmer-relevant orders with an optional USSD search filter.

    SEARCH UX:
      • buyer name
      • payment method / payment reference
      • product name inside the order
      • raw order UUID text
      • short public order code like OABC123
    """
    normalized_search = _safe_str(search_term).lower()
    search_like = f"%{normalized_search}%"
    compact_search = normalized_search.replace("-", "").replace(" ", "")
    public_code_search = compact_search[1:] if compact_search.startswith("o") else compact_search
    public_code_like = f"%{public_code_search}%"

    try:
        rows = db.session.execute(
            text(
                """
                SELECT
                    o.order_id,
                    o.order_date,
                    o.status,
                    o.delivery_status,
                    o.delivery_method,
                    o.delivered_at,
                    u.full_name AS buyer_name,
                    COALESCE(SUM(oi.line_total), 0) AS farmer_total,
                    COALESCE(p.status, 'unpaid') AS payment_status,
                    COALESCE(p.method, '-') AS payment_method,
                    COALESCE(p.reference, '-') AS payment_reference,
                    COALESCE(p.updated_at, p.created_at) AS payment_timestamp
                FROM public.orders o
                JOIN public.order_items oi ON oi.order_id = o.order_id
                JOIN public.products pr ON pr.product_id = oi.product_id
                JOIN public.users u ON u.id = o.buyer_id
                LEFT JOIN LATERAL (
                    SELECT p1.payment_id, p1.status, p1.method, p1.reference, p1.created_at, p1.updated_at
                    FROM public.payments p1
                    WHERE p1.order_id = o.order_id
                    ORDER BY COALESCE(p1.updated_at, p1.created_at) DESC
                    LIMIT 1
                ) p ON true
                WHERE pr.user_id = CAST(:farmer_id AS uuid)
                  AND (
                        :search_term = ''
                        OR LOWER(COALESCE(u.full_name, '')) LIKE :search_like
                        OR LOWER(COALESCE(p.reference, '')) LIKE :search_like
                        OR LOWER(COALESCE(p.method, '')) LIKE :search_like
                        OR LOWER(COALESCE(pr.product_name, '')) LIKE :search_like
                        OR CAST(o.order_id AS text) ILIKE :search_like
                        OR REPLACE(CAST(o.order_id AS text), '-', '') ILIKE :public_code_like
                  )
                GROUP BY
                    o.order_id, o.order_date, o.status, o.delivery_status, o.delivery_method, o.delivered_at,
                    u.full_name, p.status, p.method, p.reference, p.updated_at, p.created_at
                ORDER BY o.order_date DESC
                LIMIT :limit
                OFFSET :offset
                """
            ),
            {
                "farmer_id": farmer_id,
                "limit": max(1, limit),
                "offset": max(0, offset),
                "search_term": normalized_search,
                "search_like": search_like,
                "public_code_like": public_code_like,
            },
        ).mappings().all()
        return [dict(row) for row in rows]
    except Exception as exc:
        logger.exception("[USSD] Failed to fetch farmer orders: %s", exc)
        return []


def farmer_order_detail(farmer_id: str, order_id: str) -> Optional[dict[str, Any]]:
    """
    Return one farmer-owned order with quote-stage metadata.

    This lets the farmer set a delivery fee, mark the order ready for payment,
    and notify the customer from USSD without needing the web dashboard.
    """
    try:
        row = db.session.execute(
            text(
                """
                SELECT
                    o.order_id,
                    o.order_date,
                    o.status AS order_status,
                    o.delivery_status,
                    o.delivery_method,
                    o.delivery_address,
                    o.expected_delivery_date,
                    o.delivered_at,
                    o.delivery_fee,
                    o.delivery_fee_status,
                    u.id AS buyer_id,
                    u.full_name AS buyer_name,
                    u.phone AS buyer_phone,
                    u.location AS buyer_location,
                    COALESCE(SUM(oi.line_total), 0) AS farmer_total,
                    COALESCE(SUM(oi.quantity), 0) AS farmer_quantity,
                    COALESCE(p.payment_id, 0) AS payment_id,
                    COALESCE(p.status, 'unpaid') AS payment_status,
                    COALESCE(p.method, '-') AS payment_method,
                    COALESCE(p.reference, '-') AS payment_reference,
                    COALESCE(p.updated_at, p.created_at) AS payment_timestamp
                FROM public.orders o
                JOIN public.order_items oi ON oi.order_id = o.order_id
                JOIN public.products pr ON pr.product_id = oi.product_id
                JOIN public.users u ON u.id = o.buyer_id
                LEFT JOIN LATERAL (
                    SELECT p1.payment_id, p1.status, p1.method, p1.reference, p1.created_at, p1.updated_at
                    FROM public.payments p1
                    WHERE p1.order_id = o.order_id
                      AND (p1.user_id IS NULL OR p1.user_id = CAST(:farmer_id AS uuid))
                    ORDER BY COALESCE(p1.updated_at, p1.created_at) DESC
                    LIMIT 1
                ) p ON true
                WHERE o.order_id = CAST(:order_id AS uuid)
                  AND pr.user_id = CAST(:farmer_id AS uuid)
                GROUP BY
                    o.order_id, o.order_date, o.status, o.delivery_status, o.delivery_method,
                    o.delivery_address, o.expected_delivery_date, o.delivered_at,
                    o.delivery_fee, o.delivery_fee_status,
                    u.id, u.full_name, u.phone, u.location,
                    p.payment_id, p.status, p.method, p.reference, p.updated_at, p.created_at
                LIMIT 1
                """
            ),
            {"farmer_id": farmer_id, "order_id": order_id},
        ).mappings().first()
        return dict(row) if row else None
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to fetch farmer order detail: %s", exc)
        return None


def update_farmer_order_delivery_status(farmer_id: str, order_id: str, status_value: str) -> tuple[bool, str]:
    normalized = _safe_str(status_value).lower()
    mapped = {
        "pending": "pending",
        "in_transit": "in_transit",
        "delivered": "delivered",
        "ready": "ready",
    }.get(normalized)
    if not mapped:
        return False, "Invalid delivery status."

    detail = farmer_order_detail(farmer_id, order_id)
    if not detail:
        return False, "Order not found."

    order_status = _safe_str(detail.get("order_status")).lower()
    if order_status in {"cancelled", "canceled"}:
        return False, "Cancelled orders cannot be updated."

    delivered_at = _utcnow() if mapped == "delivered" else None
    try:
        db.session.execute(
            text(
                """
                UPDATE public.orders
                SET delivery_status = :delivery_status,
                    delivered_at = CASE
                        WHEN :delivery_status = 'delivered' THEN :delivered_at
                        ELSE NULL
                    END
                WHERE order_id = CAST(:order_id AS uuid)
                """
            ),
            {
                "order_id": order_id,
                "delivery_status": mapped,
                "delivered_at": delivered_at,
            },
        )

        db.session.execute(
            text(
                """
                UPDATE public.order_items oi
                SET delivery_status = :delivery_status
                FROM public.products pr
                WHERE oi.product_id = pr.product_id
                  AND oi.order_id = CAST(:order_id AS uuid)
                  AND pr.user_id = CAST(:farmer_id AS uuid)
                """
            ),
            {
                "order_id": order_id,
                "farmer_id": farmer_id,
                "delivery_status": mapped,
            },
        )
        db.session.commit()
        return True, f"Delivery status updated to {mapped.replace('_', ' ')}."
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to update order delivery status: %s", exc)
        return False, "Could not update delivery status."



def _notify_customer_order_ready_for_payment(*, order_row: dict[str, Any], financials: dict[str, Decimal]) -> None:
    """Best-effort dashboard + SMS alert after the farmer confirms the quote."""
    buyer_id = _safe_str(order_row.get("buyer_id"))
    buyer_phone = _safe_str(order_row.get("buyer_phone"))
    order_id = _safe_str(order_row.get("order_id"))
    order_code = _short_public_code("O", order_id)
    payment_method = _safe_str(order_row.get("payment_method"), "cash_on_delivery")
    payment_method_label = _payment_method_label(payment_method)

    message_parts = [
        f"Your order {order_code} is ready for payment.",
        f"Payment method: {payment_method_label}.",
        f"Products: {_money(financials['products_subtotal'])}.",
        f"Delivery: {_money(financials['delivery_fee'])}.",
        f"VAT: {_money(financials['vat_amount'])}.",
        f"Total: {_money(financials['grand_total'])}.",
    ]

    if _table_exists("notifications") and buyer_id and order_id:
        try:
            db.session.execute(
                text(
                    """
                    INSERT INTO public.notifications (
                        notification_id, user_id, actor_user_id, order_id,
                        notification_type, title, message, event_key,
                        data_json, is_read, created_at, updated_at
                    ) VALUES (
                        CAST(:notification_id AS uuid), CAST(:user_id AS uuid), NULL, CAST(:order_id AS uuid),
                        :notification_type, :title, :message, :event_key,
                        CAST(:data_json AS jsonb), false, :created_at, :updated_at
                    )
                    ON CONFLICT (event_key) DO UPDATE SET
                        title = EXCLUDED.title,
                        message = EXCLUDED.message,
                        data_json = EXCLUDED.data_json,
                        updated_at = EXCLUDED.updated_at,
                        is_read = false
                    """
                ),
                {
                    "notification_id": str(uuid.uuid4()),
                    "user_id": buyer_id,
                    "order_id": order_id,
                    "notification_type": "order_ready_for_payment",
                    "title": "Order ready for payment",
                    "message": " ".join(message_parts),
                    "event_key": f"ussd_order_ready:{order_id}",
                    "data_json": json.dumps(
                        {
                            "category": "orders",
                            "source": "ussd_farmer_quote",
                            "order_code": order_code,
                            "payment_method": payment_method,
                            "products_subtotal": float(financials["products_subtotal"]),
                            "delivery_fee": float(financials["delivery_fee"]),
                            "vat_amount": float(financials["vat_amount"]),
                            "grand_total": float(financials["grand_total"]),
                            "checkout_stage": "ready_for_payment",
                        },
                        ensure_ascii=False,
                    ),
                    "created_at": _utcnow(),
                    "updated_at": _utcnow(),
                },
            )
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            logger.warning("[USSD] Failed to notify customer of ready-for-payment quote: %s", exc)

    if buyer_phone:
        try:
            sms = (
                f"AgroConnect {order_code}: Products {_money(financials['products_subtotal'])}, "
                f"delivery {_money(financials['delivery_fee'])}, VAT {_money(financials['vat_amount'])}, "
                f"total {_money(financials['grand_total'])}."
            )
            if _payment_supports_reference_confirmation(payment_method):
                sms += " Open Payment Info on USSD to submit your payment ref."
            else:
                sms += " Pay cash using the quoted total when delivery/pickup is confirmed."
            _send_action_sms(
                phone_number=normalize_phone_number(buyer_phone),
                user_id=buyer_id,
                template_name="ussd_order_ready_for_payment",
                context={"order_code": order_code, "total": str(financials['grand_total'])},
                message=sms,
            )
        except Exception:
            pass


def farmer_apply_delivery_quote(*, farmer: User, order_id: str, delivery_fee: Decimal) -> tuple[bool, str]:
    """Persist the farmer quote and mark the order ready for payment."""
    detail = farmer_order_detail(str(getattr(farmer, "id")), order_id)
    if not detail:
        return False, "Order not found."

    if _safe_str(detail.get("order_status")).lower() in {"cancelled", "canceled"}:
        return False, "Cancelled orders cannot be updated."

    delivery_fee_value = _decimal_or_zero(delivery_fee).quantize(Decimal("0.01"))
    if delivery_fee_value < Decimal("0.00"):
        return False, "Delivery fee cannot be negative."

    payment_method = _safe_str(detail.get("payment_method"), "cash_on_delivery")
    if _payment_method_label(payment_method) == "EFT / Bank" and not _farmer_bank_profile_is_complete(str(getattr(farmer, "id"))):
        return False, "Complete bank profile first."

    financials = _quote_financials(detail.get("farmer_total"), delivery_fee_value)
    order_uuid = _as_uuid(order_id)
    farmer_uuid = _as_uuid(getattr(farmer, "id", None))
    if order_uuid is None or farmer_uuid is None:
        return False, "Invalid order context."

    try:
        order = db.session.get(Order, order_uuid)
        if order is None:
            return False, "Order not found."

        order.delivery_fee = delivery_fee_value
        order.delivery_fee_status = "awaiting_customer_payment"
        db.session.add(order)

        payment = (
            db.session.query(Payment)
            .filter(Payment.order_id == order_uuid, Payment.user_id == farmer_uuid)
            .order_by(Payment.updated_at.desc(), Payment.created_at.desc())
            .first()
        )
        if payment is None:
            payment = (
                db.session.query(Payment)
                .filter(Payment.order_id == order_uuid)
                .order_by(Payment.updated_at.desc(), Payment.created_at.desc())
                .first()
            )
        if payment is None:
            payment = Payment()
            payment.order_id = order_uuid
            payment.user_id = farmer_uuid
            payment.method = payment_method or "cash_on_delivery"
            payment.reference = _short_public_code("O", order_uuid)
            payment.proof_url = None

        payment.amount = financials["grand_total"]
        if _safe_str(getattr(payment, "method", None)) == "":
            payment.method = payment_method or "cash_on_delivery"
        if _safe_str(getattr(payment, "reference", None)) == "":
            payment.reference = _short_public_code("O", order_uuid)

        current_status = _safe_str(getattr(payment, "status", None), "")
        if _safe_str(getattr(payment, "method", None)).lower() in {"cash", "cash_on_delivery"}:
            if current_status not in {"paid", "refunded"}:
                payment.status = "pending"
        else:
            if current_status not in {"paid", "pending", "failed", "refunded"}:
                payment.status = "unpaid"
        payment.updated_at = _utcnow()
        db.session.add(payment)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to apply delivery quote: %s", exc)
        return False, "Could not save delivery fee."

    _notify_customer_order_ready_for_payment(order_row=detail, financials=financials)
    return True, "Delivery fee saved. Customer notified."


def _render_farmer_ready_for_payment_confirm(session: dict[str, Any], farmer: User, banner: str = "") -> UssdResponse:
    data = cast(dict[str, Any], session.get("data") or {})
    order_id = _safe_str(data.get("selected_order_id"))
    detail = farmer_order_detail(str(getattr(farmer, "id")), order_id) if order_id else None
    if not detail:
        session["state"] = STATE_FARMER_ORDERS_PAGE
        return _render_farmer_orders_page(session, farmer, banner="Order not found.")

    fee_text = _safe_str(data.get("pending_delivery_fee"))
    delivery_fee_value = _decimal_or_zero(fee_text) if fee_text else _decimal_or_zero(detail.get("delivery_fee"))
    financials = _quote_financials(detail.get("farmer_total"), delivery_fee_value)

    lines: list[str] = []
    if banner:
        lines.append(banner)
    lines.extend(
        [
            "Ready for payment",
            f"Order {_short_public_code('O', detail.get('order_id'))}",
            f"Products: {_money(financials['products_subtotal'])}",
            f"Delivery: {_money(financials['delivery_fee'])}",
            f"VAT: {_money(financials['vat_amount'])}",
            f"Total: {_money(financials['grand_total'])}",
            "1 Confirm notify customer",
            "0 Back",
        ]
    )
    return ussd_continue("\n".join(lines))


def farmer_orders_awaiting_payment_confirmation(
    farmer_id: str,
    *,
    limit: int = 5,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """
    Farmer work queue for customer-submitted payment references.

    PURPOSE:
      • keep payment verification in one short USSD screen
      • only show digital payments that still need farmer action
      • avoid mixing delivery updates with payment confirmation work
    """
    try:
        rows = db.session.execute(
            text(
                """
                SELECT
                    o.order_id,
                    o.order_date,
                    o.order_total,
                    o.delivery_method,
                    o.delivery_status,
                    o.buyer_id,
                    u.full_name AS buyer_name,
                    u.phone AS buyer_phone,
                    COALESCE(p.payment_id, 0) AS payment_id,
                    COALESCE(p.status, 'unpaid') AS payment_status,
                    COALESCE(p.method, '-') AS payment_method,
                    COALESCE(p.reference, '') AS payment_reference,
                    COALESCE(p.updated_at, p.created_at) AS payment_timestamp
                FROM public.orders o
                JOIN public.users u ON u.id = o.buyer_id
                JOIN LATERAL (
                    SELECT p1.payment_id, p1.status, p1.method, p1.reference, p1.created_at, p1.updated_at, p1.user_id
                    FROM public.payments p1
                    WHERE p1.order_id = o.order_id
                      AND (p1.user_id IS NULL OR p1.user_id = CAST(:farmer_id AS uuid))
                    ORDER BY COALESCE(p1.updated_at, p1.created_at) DESC
                    LIMIT 1
                ) p ON true
                WHERE EXISTS (
                    SELECT 1
                    FROM public.order_items oi
                    JOIN public.products pr ON pr.product_id = oi.product_id
                    WHERE oi.order_id = o.order_id
                      AND pr.user_id = CAST(:farmer_id AS uuid)
                )
                  AND LOWER(COALESCE(p.status, '')) = 'pending'
                  AND LOWER(COALESCE(p.method, '')) IN ('eft', 'bank', 'bank transfer', 'mobile_wallet', 'wallet', 'ewallet')
                  AND TRIM(COALESCE(p.reference, '')) <> ''
                ORDER BY COALESCE(p.updated_at, p.created_at) DESC, o.order_date DESC
                LIMIT :limit
                OFFSET :offset
                """
            ),
            {
                "farmer_id": farmer_id,
                "limit": max(1, limit),
                "offset": max(0, offset),
            },
        ).mappings().all()
        return [dict(row) for row in rows]
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to fetch payment confirmation queue: %s", exc)
        return []


def farmer_payment_confirmation_detail(farmer_id: str, order_id: str) -> Optional[dict[str, Any]]:
    """Return one queue item for payment review."""
    rows = farmer_orders_awaiting_payment_confirmation(farmer_id, limit=50, offset=0)
    for row in rows:
        if _safe_str(row.get("order_id")) == _safe_str(order_id):
            return row
    return None


def _notify_customer_of_payment_decision(
    *,
    order_row: dict[str, Any],
    approved: bool,
) -> None:
    """Best-effort customer notification after farmer payment review."""
    buyer_id = _safe_str(order_row.get("buyer_id"))
    buyer_phone = _safe_str(order_row.get("buyer_phone"))
    order_id = _safe_str(order_row.get("order_id"))
    order_code = _short_public_code("O", order_id)
    method_label = _payment_method_label(order_row.get("payment_method"))
    reference_value = _safe_str(order_row.get("payment_reference"), "-")

    title = "Payment confirmed" if approved else "Payment reference rejected"
    message = (
        f"Your {method_label} payment for {order_code} was confirmed."
        if approved
        else f"Your {method_label} payment reference for {order_code} needs correction."
    )

    if _table_exists("notifications") and buyer_id and order_id:
        try:
            db.session.execute(
                text(
                    """
                    INSERT INTO public.notifications (
                        notification_id, user_id, actor_user_id, order_id,
                        notification_type, title, message, event_key,
                        data_json, is_read, created_at, updated_at
                    ) VALUES (
                        CAST(:notification_id AS uuid), CAST(:user_id AS uuid), CAST(:actor_user_id AS uuid), CAST(:order_id AS uuid),
                        :notification_type, :title, :message, :event_key,
                        CAST(:data_json AS jsonb), false, :created_at, :updated_at
                    )
                    ON CONFLICT (event_key) DO UPDATE SET
                        title = EXCLUDED.title,
                        message = EXCLUDED.message,
                        data_json = EXCLUDED.data_json,
                        updated_at = EXCLUDED.updated_at,
                        is_read = false
                    """
                ),
                {
                    "notification_id": str(uuid.uuid4()),
                    "user_id": buyer_id,
                    "actor_user_id": None,
                    "order_id": order_id,
                    "notification_type": "payment_review",
                    "title": title,
                    "message": message,
                    "event_key": f"payment_review:{order_id}:{'approved' if approved else 'rejected'}",
                    "data_json": json.dumps(
                        {
                            "category": "orders",
                            "source": "ussd_farmer_review",
                            "payment_confirmation_status": "paid" if approved else "failed",
                            "payment_reference": reference_value,
                            "payment_method": _safe_str(order_row.get("payment_method")),
                            "order_code": order_code,
                        },
                        ensure_ascii=False,
                    ),
                    "created_at": _utcnow(),
                    "updated_at": _utcnow(),
                },
            )
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            logger.warning("[USSD] Failed to notify customer via notifications: %s", exc)

    if buyer_phone:
        try:
            sms = (
                f"AgroConnect {order_code}: Payment confirmed. Thank you."
                if approved
                else f"AgroConnect {order_code}: Payment ref rejected. Please review Payment Info and submit the correct ref."
            )
            _send_action_sms(
                phone_number=normalize_phone_number(buyer_phone),
                user_id=buyer_id,
                template_name="ussd_payment_review_approved" if approved else "ussd_payment_review_rejected",
                context={"order_code": order_code, "payment_reference": reference_value},
                message=sms,
            )
        except Exception:
            pass


def farmer_review_payment_reference(*, farmer_id: str, order_id: str, approved: bool) -> tuple[bool, str]:
    """Confirm or reject a customer-submitted payment reference."""
    row = farmer_payment_confirmation_detail(farmer_id, order_id)
    if not row:
        return False, "Payment confirmation not found."

    payment_id = row.get("payment_id")
    if payment_id is None:
        return False, "Payment record not found."

    try:
        payment = db.session.get(Payment, int(payment_id))
    except Exception:
        payment = None
    if payment is None:
        return False, "Payment record not found."

    try:
        payment.status = "paid" if approved else "failed"
        payment.updated_at = _utcnow()
        db.session.add(payment)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to review payment reference: %s", exc)
        return False, "Could not update payment status."

    _notify_customer_of_payment_decision(order_row=row, approved=approved)
    return True, "Payment confirmed." if approved else "Payment reference rejected."

def farmer_monthly_paid_sales(farmer_id: str) -> tuple[Decimal, int]:
    now = _utcnow()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if month_start.month == 12:
        next_month = month_start.replace(year=month_start.year + 1, month=1)
    else:
        next_month = month_start.replace(month=month_start.month + 1)

    paid_orders_subq = (
        select(Payment.order_id)
        .where(Payment.status == "paid")
        .where(func.coalesce(Payment.updated_at, Payment.created_at) >= month_start)
        .where(func.coalesce(Payment.updated_at, Payment.created_at) < next_month)
        .distinct()
        .subquery()
    )

    stmt = (
        select(
            func.coalesce(func.sum(OrderItem.line_total), 0).label("total_sales"),
            func.count(func.distinct(OrderItem.order_id)).label("orders_count"),
        )
        .select_from(OrderItem)
        .join(Product, Product.product_id == OrderItem.product_id)
        .where(Product.user_id == uuid.UUID(farmer_id))
        .where(OrderItem.order_id.in_(select(paid_orders_subq.c.order_id)))
    )

    row = db.session.execute(stmt).one()
    return Decimal(str(row.total_sales or 0)), int(row.orders_count or 0)


def farmer_low_stock_alerts(farmer_id: str, *, limit: int = 4) -> list[str]:
    threshold = _farmer_low_stock_threshold(farmer_id)
    alerts: list[str] = []

    if _table_exists("ai_stock_alerts"):
        try:
            rows = db.session.execute(
                text(
                    """
                    SELECT p.product_name, a.severity, a.recommended_restock
                    FROM public.ai_stock_alerts a
                    JOIN public.products p ON p.product_id = a.product_id
                    WHERE a.farmer_id = CAST(:farmer_id AS uuid)
                      AND COALESCE(a.resolved, false) = false
                    ORDER BY a.computed_at DESC
                    LIMIT :limit
                    """
                ),
                {"farmer_id": farmer_id, "limit": limit},
            ).mappings().all()

            for row in rows:
                product_name = _safe_str(row.get("product_name"), "Product")
                recommended = row.get("recommended_restock")
                if recommended is not None:
                    alerts.append(f"{product_name[:18]} -> restock {recommended}")
                else:
                    alerts.append(f"{product_name[:18]} -> attention needed")
        except Exception as exc:
            logger.warning("[USSD] AI stock alert query failed: %s", exc)

    if alerts:
        return alerts[:limit]

    stmt = (
        select(Product.product_name, Product.quantity)
        .where(Product.user_id == uuid.UUID(farmer_id))
        .where(Product.quantity <= Decimal(str(threshold)))
        .order_by(Product.quantity.asc(), Product.created_at.desc())
        .limit(limit)
    )

    rows = db.session.execute(stmt).all()
    for row in rows:
        alerts.append(f"{_safe_str(row.product_name)[:18]} -> qty {row.quantity}")
    return alerts



def _bank_code_for_bank_name(bank_name: Any) -> str:
    """
    Return a short bank code shown in the USSD bank profile screen.

    The farmer still enters the EFT / branch code separately. This short code
    is only a compact bank identifier for the USSD display.
    """
    normalized = _safe_str(bank_name).lower()
    for payload in BANK_PROFILE_BANK_CHOICES.values():
        if _safe_str(payload.get("name")).lower() == normalized:
            return _safe_str(payload.get("code"), "-")
    if not normalized:
        return "-"
    parts = [part[:1].upper() for part in normalized.replace("-", " ").split() if part]
    return "".join(parts)[:6] or "-"


def _bank_profile_bank_menu() -> str:
    lines = ["Choose bank"]
    for key, payload in BANK_PROFILE_BANK_CHOICES.items():
        lines.append(f"{key} {_short_text(payload.get('name'), 14)} ({payload.get('code')})")
    lines.append("0 Back")
    return "\n".join(lines)


def _farmer_payment_profile_row(farmer_id: str) -> Optional[dict[str, Any]]:
    if not _table_exists("farmer_payment_profiles"):
        return None

    try:
        row = db.session.execute(
            text(
                """
                SELECT
                    profile_id,
                    farmer_id,
                    bank_name,
                    account_name,
                    account_number,
                    branch_code,
                    branch_town,
                    payment_instructions,
                    use_for_eft,
                    is_active,
                    created_at,
                    updated_at
                FROM public.farmer_payment_profiles
                WHERE farmer_id = CAST(:farmer_id AS uuid)
                  AND COALESCE(is_active, true) = true
                ORDER BY updated_at DESC NULLS LAST, created_at DESC
                LIMIT 1
                """
            ),
            {"farmer_id": farmer_id},
        ).mappings().first()
        return dict(row) if row else None
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to fetch farmer payment profile row: %s", exc)
        return None


def _masked_account_number(account_number: Any) -> str:
    raw = _safe_str(account_number)
    return f"****{raw[-4:]}" if raw and len(raw) >= 4 else "not set"


def _farmer_payment_profile_lines(row: Optional[dict[str, Any]]) -> list[str]:
    if not row:
        return ["No active bank profile set."]

    bank_name = _safe_str(row.get("bank_name"), "Bank")
    bank_code = _bank_code_for_bank_name(bank_name)
    account_name = _safe_str(row.get("account_name"), "Account")
    branch_code = _safe_str(row.get("branch_code"), "not set")
    branch_town = _safe_str(row.get("branch_town"), "not set")
    payment_ref = _safe_str(row.get("payment_instructions"), "not set")

    return [
        bank_name,
        f"Code: {bank_code}",
        f"Name: {_short_text(account_name, 14, 'not set')}",
        f"Acc: {_masked_account_number(row.get('account_number'))}",
        f"Branch: {_short_text(branch_code, 14, 'not set')}",
        f"Town: {_short_text(branch_town, 14, 'not set')}",
        f"Ref: {_short_text(payment_ref, 14, 'not set')}",
    ]


def upsert_farmer_payment_profile(
    farmer_id: str,
    *,
    bank_name: Optional[str] = None,
    account_name: Optional[str] = None,
    account_number: Optional[str] = None,
    branch_code: Optional[str] = None,
    branch_town: Optional[str] = None,
    payment_instructions: Optional[str] = None,
) -> tuple[bool, str]:
    """
    Create or update the farmer EFT profile.

    The function merges the new field from the active USSD screen with the
    farmer's existing row so that untouched values are preserved.
    """
    if not _table_exists("farmer_payment_profiles"):
        return False, "Bank profile table not available."

    current = _farmer_payment_profile_row(farmer_id) or {}
    profile_id = _safe_str(current.get("profile_id")) or str(uuid.uuid4())

    merged_bank_name = _safe_str(bank_name if bank_name is not None else current.get("bank_name")) or None
    merged_account_name = _safe_str(account_name if account_name is not None else current.get("account_name")) or None
    merged_account_number = _safe_str(account_number if account_number is not None else current.get("account_number")) or None
    merged_branch_code = _safe_str(branch_code if branch_code is not None else current.get("branch_code")) or None
    merged_branch_town = _safe_str(branch_town if branch_town is not None else current.get("branch_town")) or None
    merged_payment_ref = _safe_str(
        payment_instructions if payment_instructions is not None else current.get("payment_instructions")
    ) or None

    try:
        db.session.execute(
            text(
                """
                INSERT INTO public.farmer_payment_profiles (
                    profile_id,
                    farmer_id,
                    bank_name,
                    account_name,
                    account_number,
                    branch_code,
                    payment_instructions,
                    use_for_eft,
                    is_active,
                    created_at,
                    updated_at,
                    branch_town
                ) VALUES (
                    CAST(:profile_id AS uuid),
                    CAST(:farmer_id AS uuid),
                    :bank_name,
                    :account_name,
                    :account_number,
                    :branch_code,
                    :payment_instructions,
                    true,
                    true,
                    COALESCE(:created_at, NOW()),
                    :updated_at,
                    :branch_town
                )
                ON CONFLICT (farmer_id)
                DO UPDATE SET
                    bank_name = EXCLUDED.bank_name,
                    account_name = EXCLUDED.account_name,
                    account_number = EXCLUDED.account_number,
                    branch_code = EXCLUDED.branch_code,
                    payment_instructions = EXCLUDED.payment_instructions,
                    use_for_eft = true,
                    is_active = true,
                    updated_at = EXCLUDED.updated_at,
                    branch_town = EXCLUDED.branch_town
                """
            ),
            {
                "profile_id": profile_id,
                "farmer_id": farmer_id,
                "bank_name": merged_bank_name,
                "account_name": merged_account_name,
                "account_number": merged_account_number,
                "branch_code": merged_branch_code,
                "payment_instructions": merged_payment_ref,
                "created_at": current.get("created_at"),
                "updated_at": _utcnow(),
                "branch_town": merged_branch_town,
            },
        )
        db.session.commit()
        return True, "Bank profile updated successfully."
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to upsert farmer payment profile: %s", exc)
        return False, "Could not update bank profile."


def _render_farmer_bank_profile_menu(session: dict[str, Any], farmer: User, banner: str = "") -> UssdResponse:
    row = _farmer_payment_profile_row(str(getattr(farmer, "id")))

    lines: list[str] = []
    if banner:
        lines.append(banner)
    lines.append("Bank Profile")

    if row:
        # Keep the menu compact but still show the most important fields.
        lines.extend(_farmer_payment_profile_lines(row)[:4])
    else:
        lines.append("No bank profile yet.")

    lines.extend(
        [
            "1 View current",
            "2 Change bank",
            "3 Account name",
            "4 Account number",
            "5 Branch code",
            "6 Branch town",
            "7 Payment ref",
            "0 Back",
        ]
    )
    return ussd_continue("\n".join(lines))


def farmer_payment_profile_status(farmer_id: str) -> str:
    """
    Compact bank profile summary used in view screens.

    USSD NOTE:
      • shows both bank name and short bank code
      • shows only a masked account number
      • includes branch code and branch town for EFT confirmation
    """
    if not _table_exists("farmer_payment_profiles"):
        return "Bank profile table not available."

    row = _farmer_payment_profile_row(farmer_id)
    if not row:
        return "No active bank profile set."

    return "\n".join(_farmer_payment_profile_lines(row))


def farmer_manageable_products(
    farmer_id: str,
    *,
    limit: int = 5,
    offset: int = 0,
    search_term: str = "",
) -> list[dict[str, Any]]:
    """
    Return the farmer's products ordered by recent activity.

    SEARCH UX:
      • product name
      • category
      • status
      • rejection reason
      • raw UUID text
      • short public product code like PABC123
    """
    normalized_search = _safe_str(search_term).lower()
    search_like = f"%{normalized_search}%"
    compact_search = normalized_search.replace("-", "").replace(" ", "")
    public_code_search = compact_search[1:] if compact_search.startswith("p") else compact_search
    public_code_like = f"%{public_code_search}%"

    try:
        rows = db.session.execute(
            text(
                """
                SELECT
                    product_id,
                    product_name,
                    description,
                    category,
                    price,
                    quantity,
                    unit,
                    status,
                    rejection_reason,
                    COALESCE(status_updated_at, updated_at, submitted_at, created_at) AS activity_at
                FROM public.products
                WHERE user_id = CAST(:farmer_id AS uuid)
                  AND LOWER(COALESCE(status, '')) <> 'deleted'
                  AND (
                        :search_term = ''
                        OR LOWER(COALESCE(product_name, '')) LIKE :search_like
                        OR LOWER(COALESCE(category, '')) LIKE :search_like
                        OR LOWER(COALESCE(status, '')) LIKE :search_like
                        OR LOWER(COALESCE(rejection_reason, '')) LIKE :search_like
                        OR CAST(product_id AS text) ILIKE :search_like
                        OR REPLACE(CAST(product_id AS text), '-', '') ILIKE :public_code_like
                  )
                ORDER BY
                    CASE
                        WHEN LOWER(COALESCE(status, '')) IN ('available', 'approved', 'published', 'rejected') THEN 0
                        WHEN LOWER(COALESCE(status, '')) = 'pending' THEN 1
                        ELSE 2
                    END,
                    COALESCE(status_updated_at, updated_at, submitted_at, created_at) DESC,
                    product_name ASC
                LIMIT :limit
                OFFSET :offset
                """
            ),
            {
                "farmer_id": farmer_id,
                "limit": max(1, limit),
                "offset": max(0, offset),
                "search_term": normalized_search,
                "search_like": search_like,
                "public_code_like": public_code_like,
            },
        ).mappings().all()
        return [dict(row) for row in rows]
    except Exception as exc:
        logger.exception("[USSD] Failed to fetch farmer products: %s", exc)
        return []


def farmer_product_detail(farmer_id: str, product_id: str) -> Optional[Product]:
    try:
        product = db.session.get(Product, uuid.UUID(product_id))
    except Exception:
        product = None
    if product is None:
        return None
    if str(getattr(product, "user_id", "")) != farmer_id:
        return None
    if _safe_str(getattr(product, "status", "")).lower() == "deleted":
        return None
    return cast(Product, product)


def update_product_for_farmer(*, farmer: User, product: Product, field_name: str, value: Any) -> tuple[bool, str]:
    before_status = _safe_str(getattr(product, "status", "")).lower()
    try:
        if field_name == "product_name":
            product.product_name = _safe_str(value)[:200]
        elif field_name == "description":
            product.description = _safe_str(value)[:500]
        elif field_name == "category":
            product.category = _safe_str(value)[:100]
        elif field_name == "price":
            decimal_value = _decimal_from_input(value)
            if decimal_value is None:
                return False, "Invalid price."
            product.price = decimal_value
        elif field_name == "quantity":
            decimal_value = _decimal_from_input(value)
            if decimal_value is None:
                return False, "Invalid quantity."
            product.quantity = decimal_value
        elif field_name == "unit":
            product.unit = _safe_str(value)[:20]
        else:
            return False, "Unsupported update field."

        if hasattr(product, "last_edited_by"):
            setattr(product, "last_edited_by", getattr(farmer, "id", None))
        if hasattr(product, "last_edited_at"):
            setattr(product, "last_edited_at", _utcnow())

        db.session.add(product)
        db.session.commit()
        db.session.refresh(product)

        after_status = _safe_str(getattr(product, "status", "")).lower()
        if after_status == "pending" and before_status in {"available", "approved", "published", "rejected"}:
            return True, "Updated. Listing sent back for admin review."
        if after_status == "pending":
            return True, "Updated successfully. Listing is pending review."
        return True, "Updated successfully."
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to update product: %s", exc)
        return False, "Could not update product."


def delete_product_for_farmer(*, farmer: User, product: Product) -> tuple[bool, str]:
    try:
        has_orders = db.session.execute(
            select(OrderItem.order_item_id).where(OrderItem.product_id == getattr(product, "product_id")).limit(1)
        ).first() is not None

        if has_orders:
            product.status = "deleted"
            product.quantity = Decimal("0")
            if hasattr(product, "last_edited_by"):
                setattr(product, "last_edited_by", getattr(farmer, "id", None))
            if hasattr(product, "last_edited_at"):
                setattr(product, "last_edited_at", _utcnow())
            if hasattr(product, "status_updated_at"):
                setattr(product, "status_updated_at", _utcnow())
            db.session.add(product)
            db.session.commit()
            return True, "Product removed from active catalog."

        db.session.delete(product)
        db.session.commit()
        return True, "Product deleted successfully."
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to delete product: %s", exc)
        return False, "Could not delete product."


def farmer_product_demand_prediction(farmer_id: str, product_id: str) -> str:
    product = farmer_product_detail(farmer_id, product_id)
    if product is None:
        return "Demand Insight\nProduct not found."

    product_name = _safe_str(getattr(product, "product_name", "Product"), "Product")

    if _table_exists("ai_stock_alerts"):
        try:
            row = db.session.execute(
                text(
                    """
                    SELECT severity, predicted_demand, available_stock, recommended_restock, computed_at
                    FROM public.ai_stock_alerts
                    WHERE farmer_id = CAST(:farmer_id AS uuid)
                      AND product_id = CAST(:product_id AS uuid)
                    ORDER BY computed_at DESC
                    LIMIT 1
                    """
                ),
                {"farmer_id": farmer_id, "product_id": product_id},
            ).mappings().first()
            if row:
                severity = _safe_str(row.get("severity"), "medium").title()
                predicted = row.get("predicted_demand") or 0
                available = row.get("available_stock") or 0
                restock = row.get("recommended_restock") or 0
                return (
                    f"Demand Insight\n{product_name[:18]}\n"
                    f"{severity} demand\nPred: {predicted}\nStock: {available}\nRestock: {restock}"
                )
        except Exception as exc:
            logger.warning("[USSD] AI demand insight query failed: %s", exc)

    if _table_exists("market_trends"):
        try:
            row = db.session.execute(
                text(
                    """
                    SELECT demand_index, avg_price, timestamp
                    FROM public.market_trends
                    WHERE product_id = CAST(:product_id AS uuid)
                    ORDER BY timestamp DESC
                    LIMIT 1
                    """
                ),
                {"product_id": product_id},
            ).mappings().first()
            if row:
                demand_index = int(row.get("demand_index") or 0)
                label = "High" if demand_index >= 70 else "Medium" if demand_index >= 40 else "Low"
                return (
                    f"Demand Insight\n{product_name[:18]}\n"
                    f"{label} demand\nIndex: {demand_index}\nAvg price: {_money(row.get('avg_price'))}"
                )
        except Exception as exc:
            logger.warning("[USSD] Market trend query failed: %s", exc)

    try:
        sold_30 = db.session.execute(
            text(
                """
                SELECT COALESCE(SUM(oi.quantity), 0) AS qty_sold
                FROM public.order_items oi
                JOIN public.orders o ON o.order_id = oi.order_id
                LEFT JOIN public.payments p ON p.order_id = o.order_id
                WHERE oi.product_id = CAST(:product_id AS uuid)
                  AND o.order_date >= NOW() - INTERVAL '30 days'
                  AND LOWER(COALESCE(p.status, 'paid')) = 'paid'
                """
            ),
            {"product_id": product_id},
        ).scalar()
        sold_30_decimal = Decimal(str(sold_30 or 0))
        stock_decimal = Decimal(str(getattr(product, "quantity", 0) or 0))
        if sold_30_decimal >= stock_decimal and sold_30_decimal > 0:
            label = "High"
            tip = "Restock soon"
        elif sold_30_decimal >= (stock_decimal / Decimal("2")) and sold_30_decimal > 0:
            label = "Medium"
            tip = "Monitor stock"
        else:
            label = "Low"
            tip = "Demand stable"
        return (
            f"Demand Insight\n{product_name[:18]}\n"
            f"{label} demand\n30d sold: {sold_30_decimal}\nStock: {stock_decimal}\nTip: {tip}"
        )
    except Exception as exc:
        logger.warning("[USSD] Fallback demand estimate failed: %s", exc)
        return f"Demand Insight\n{product_name[:18]}\nNo prediction yet."




def farmer_product_rejection_summary(farmer_id: str, product_id: str) -> str:
    product = farmer_product_detail(farmer_id, product_id)
    if product is None:
        return "Rejection Review\nProduct not found.\n0 Back"

    status_value = _safe_str(getattr(product, "status", "")).lower()
    if status_value != "rejected":
        return "Rejection Review\nThis product is not rejected.\n0 Back"

    reason = _safe_str(getattr(product, "rejection_reason", ""), "No rejection reason recorded.")
    latest_review_note = ""

    if _table_exists("product_moderation_events"):
        try:
            row = db.session.execute(
                text(
                    """
                    SELECT notes
                    FROM public.product_moderation_events
                    WHERE product_id = CAST(:product_id AS uuid)
                      AND LOWER(COALESCE(action, '')) = 'rejected'
                    ORDER BY created_at DESC
                    LIMIT 1
                    """
                ),
                {"product_id": product_id},
            ).mappings().first()
            if row:
                latest_review_note = _safe_str(row.get("notes"))
        except Exception as exc:
            logger.warning("[USSD] Failed to fetch rejection note: %s", exc)

    lines = [
        "Rejection Review",
        _short_text(getattr(product, "product_name", ""), 18, "Product"),
        f"Reason: {_short_text(reason, 55, 'Not recorded')}",
    ]
    if latest_review_note:
        lines.append(f"Note: {_short_text(latest_review_note, 55, '-')}")
    lines.extend(["1 Lodge appeal", "0 Back"])
    return "\n".join(lines)


def _notify_admins_of_product_appeal(*, farmer: User, product: Product, appeal_text: str) -> None:
    if not _table_exists("notifications"):
        return

    try:
        admin_ids = [
            str(admin_id)
            for admin_id in db.session.execute(
                select(User.id).where(User.role == ROLE_ADMIN).where(User.is_active.is_(True))
            ).scalars().all()
        ]
    except Exception as exc:
        logger.warning("[USSD] Failed to resolve admins for product appeal: %s", exc)
        return

    if not admin_ids:
        return

    product_id = str(getattr(product, "product_id", "") or "")
    farmer_id = str(getattr(farmer, "id", "") or "")
    product_name = _safe_str(getattr(product, "product_name", ""), "Product")
    farmer_name = _safe_str(getattr(farmer, "full_name", ""), "Farmer")

    try:
        for admin_id in admin_ids:
            db.session.execute(
                text(
                    """
                    INSERT INTO public.notifications (
                        notification_id, user_id, actor_user_id, notification_type,
                        title, message, data_json, is_read, created_at, updated_at
                    ) VALUES (
                        CAST(:notification_id AS uuid), CAST(:user_id AS uuid), CAST(:actor_user_id AS uuid), :notification_type,
                        :title, :message, CAST(:data_json AS jsonb), false, :created_at, :updated_at
                    )
                    """
                ),
                {
                    "notification_id": str(uuid.uuid4()),
                    "user_id": admin_id,
                    "actor_user_id": farmer_id or None,
                    "notification_type": "product_review",
                    "title": "Product appeal submitted",
                    "message": f"{farmer_name} appealed {product_name}.",
                    "data_json": json.dumps(
                        {
                            "category": "moderation",
                            "source": "ussd",
                            "action": "appeal",
                            "product_id": product_id,
                            "product_name": product_name,
                            "appeal_text": appeal_text,
                        },
                        ensure_ascii=False,
                    ),
                    "created_at": _utcnow(),
                    "updated_at": _utcnow(),
                },
            )
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.warning("[USSD] Failed to notify admins of appeal: %s", exc)


def lodge_farmer_product_appeal(*, farmer: User, product: Product, appeal_text: str) -> tuple[bool, str]:
    status_value = _safe_str(getattr(product, "status", "")).lower()
    if status_value != "rejected":
        return False, "Only rejected products can be appealed."

    appeal_message = _safe_str(appeal_text)[:500]
    if len(appeal_message) < 5:
        return False, "Appeal message is too short."

    previous_reason = _safe_str(getattr(product, "rejection_reason", ""))
    now = _utcnow()

    try:
        if hasattr(product, "last_edited_by"):
            setattr(product, "last_edited_by", getattr(farmer, "id", None))
        if hasattr(product, "last_edited_at"):
            setattr(product, "last_edited_at", now)
        if hasattr(product, "reviewed_at"):
            setattr(product, "reviewed_at", None)
        if hasattr(product, "reviewed_by"):
            setattr(product, "reviewed_by", None)
        if hasattr(product, "status_updated_at"):
            setattr(product, "status_updated_at", now)
        if hasattr(product, "submitted_at"):
            setattr(product, "submitted_at", now)
        if hasattr(product, "rejection_reason"):
            setattr(product, "rejection_reason", None)
        if hasattr(product, "moderation_changes"):
            setattr(
                product,
                "moderation_changes",
                {
                    "changed_fields": [],
                    "appeal_text": appeal_message,
                    "appeal_submitted_at": now.isoformat(),
                    "pending_reason": "appealed_by_farmer",
                    "previous_status": status_value or "rejected",
                    "previous_rejection_reason": previous_reason or None,
                },
            )

        setattr(product, "status", "pending")
        db.session.add(product)

        if _table_exists("product_moderation_events"):
            db.session.execute(
                text(
                    """
                    INSERT INTO public.product_moderation_events (
                        id, product_id, action, actor_role, actor_id, created_at,
                        changed_fields_json, before_json, after_json, notes
                    ) VALUES (
                        :id, CAST(:product_id AS uuid), :action, :actor_role, :actor_id, :created_at,
                        :changed_fields_json, :before_json, :after_json, :notes
                    )
                    """
                ),
                {
                    "id": str(uuid.uuid4()),
                    "product_id": str(getattr(product, "product_id")),
                    "action": "appealed",
                    "actor_role": "farmer",
                    "actor_id": str(getattr(farmer, "id")),
                    "created_at": now,
                    "changed_fields_json": json.dumps([], ensure_ascii=False),
                    "before_json": json.dumps({"status": status_value or "rejected", "rejection_reason": previous_reason or None}, ensure_ascii=False),
                    "after_json": json.dumps({"status": "pending"}, ensure_ascii=False),
                    "notes": appeal_message,
                },
            )

        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to lodge product appeal: %s", exc)
        return False, "Could not submit appeal."

    _notify_admins_of_product_appeal(farmer=farmer, product=product, appeal_text=appeal_message)
    return True, "Appeal submitted. Product sent for re-review."


def customer_latest_orders(customer_id: str, *, limit: int = 3, offset: int = 0) -> list[dict[str, Any]]:
    """Recent customer orders with quote-stage fields for Payment Info."""
    try:
        rows = db.session.execute(
            text(
                """
                SELECT
                    o.order_id,
                    o.order_date,
                    o.status,
                    o.order_total,
                    o.delivery_method,
                    o.delivery_fee,
                    o.delivery_fee_status,
                    o.delivery_address,
                    COALESCE(p.status, 'unpaid') AS payment_status,
                    COALESCE(p.method, '-') AS payment_method,
                    COALESCE(p.reference, '-') AS payment_reference
                FROM public.orders o
                LEFT JOIN LATERAL (
                    SELECT p1.payment_id, p1.status, p1.method, p1.reference
                    FROM public.payments p1
                    WHERE p1.order_id = o.order_id
                    ORDER BY COALESCE(p1.updated_at, p1.created_at) DESC
                    LIMIT 1
                ) p ON true
                WHERE o.buyer_id = CAST(:customer_id AS uuid)
                ORDER BY o.order_date DESC
                LIMIT :limit
                OFFSET :offset
                """
            ),
            {"customer_id": customer_id, "limit": max(1, limit), "offset": max(0, offset)},
        ).mappings().all()
        return [dict(row) for row in rows]
    except Exception as exc:
        logger.exception("[USSD] Failed to fetch customer orders: %s", exc)
        return []


def customer_order_detail(customer_id: str, order_id: str) -> Optional[dict[str, Any]]:
    """Return one customer-owned order with quote-stage and seller context."""
    try:
        row = db.session.execute(
            text(
                """
                SELECT
                    o.order_id,
                    o.order_date,
                    o.status,
                    o.order_total,
                    o.delivery_method,
                    o.delivery_status,
                    o.delivery_fee,
                    o.delivery_fee_status,
                    o.delivery_address,
                    COALESCE(p.status, 'unpaid') AS payment_status,
                    COALESCE(p.method, '-') AS payment_method,
                    COALESCE(p.reference, '-') AS payment_reference,
                    COUNT(oi.order_item_id) AS item_count,
                    COALESCE(SUM(oi.quantity), 0) AS total_qty,
                    MIN(COALESCE(pr.product_name, 'Product')) AS lead_product_name,
                    MIN(COALESCE(u.full_name, 'Farmer')) AS farmer_name,
                    MIN(COALESCE(u.location, '')) AS farmer_location
                FROM public.orders o
                LEFT JOIN public.order_items oi ON oi.order_id = o.order_id
                LEFT JOIN public.products pr ON pr.product_id = oi.product_id
                LEFT JOIN public.users u ON u.id = pr.user_id
                LEFT JOIN LATERAL (
                    SELECT p1.payment_id, p1.status, p1.method, p1.reference
                    FROM public.payments p1
                    WHERE p1.order_id = o.order_id
                    ORDER BY COALESCE(p1.updated_at, p1.created_at) DESC
                    LIMIT 1
                ) p ON true
                WHERE o.buyer_id = CAST(:customer_id AS uuid)
                  AND o.order_id = CAST(:order_id AS uuid)
                GROUP BY
                    o.order_id, o.order_date, o.status, o.order_total, o.delivery_method,
                    o.delivery_status, o.delivery_fee, o.delivery_fee_status, o.delivery_address,
                    p.status, p.method, p.reference
                LIMIT 1
                """
            ),
            {"customer_id": customer_id, "order_id": order_id},
        ).mappings().first()
        return dict(row) if row else None
    except Exception as exc:
        logger.exception("[USSD] Failed to fetch customer order detail: %s", exc)
        return None


def customer_category_rows(*, limit: int = 6) -> list[dict[str, Any]]:
    try:
        rows = db.session.execute(
            text(
                """
                SELECT category, COUNT(*) AS item_count
                FROM public.products
                WHERE LOWER(COALESCE(status, '')) IN ('available', 'approved', 'active', 'published')
                  AND category IS NOT NULL
                  AND TRIM(category) <> ''
                  AND COALESCE(quantity, 0) > 0
                GROUP BY category
                ORDER BY COUNT(*) DESC, category ASC
                LIMIT :limit
                """
            ),
            {"limit": max(1, limit)},
        ).mappings().all()
        return [
            {
                "category": _safe_str(row.get("category")),
                "item_count": int(row.get("item_count") or 0),
            }
            for row in rows
            if _safe_str(row.get("category"))
        ]
    except Exception as exc:
        logger.exception("[USSD] Failed to fetch customer category rows: %s", exc)
        return []


def customer_searchable_products(
    *,
    search_term: str = "",
    category: str = "",
    limit: int = 4,
    offset: int = 0,
) -> list[dict[str, Any]]:
    normalized_search = _safe_str(search_term).lower()
    search_like = f"%{normalized_search}%"
    category_value = _safe_str(category)

    try:
        rows = db.session.execute(
            text(
                """
                SELECT
                    p.product_id,
                    p.product_name,
                    p.description,
                    p.category,
                    p.price,
                    p.quantity,
                    p.unit,
                    p.status,
                    u.id AS farmer_id,
                    u.full_name AS farmer_name,
                    u.location AS farmer_location
                FROM public.products p
                LEFT JOIN public.users u ON u.id = p.user_id
                WHERE LOWER(COALESCE(p.status, '')) IN ('available', 'approved', 'active', 'published')
                  AND COALESCE(p.quantity, 0) > 0
                  AND (
                        :search_term = ''
                        OR LOWER(COALESCE(p.product_name, '')) LIKE :search_like
                        OR LOWER(COALESCE(p.category, '')) LIKE :search_like
                        OR LOWER(COALESCE(p.description, '')) LIKE :search_like
                        OR CAST(p.product_id AS text) ILIKE :search_like
                  )
                  AND (
                        :category = ''
                        OR LOWER(COALESCE(p.category, '')) = LOWER(:category)
                  )
                ORDER BY LOWER(COALESCE(p.product_name, '')) ASC, p.created_at DESC NULLS LAST
                LIMIT :limit
                OFFSET :offset
                """
            ),
            {
                "search_term": normalized_search,
                "search_like": search_like,
                "category": category_value,
                "limit": max(1, limit),
                "offset": max(0, offset),
            },
        ).mappings().all()
        return [dict(row) for row in rows]
    except Exception as exc:
        logger.exception("[USSD] Failed to search customer products: %s", exc)
        return []


def customer_product_detail(product_id: str) -> Optional[dict[str, Any]]:
    try:
        row = db.session.execute(
            text(
                """
                SELECT
                    p.product_id,
                    p.product_name,
                    p.description,
                    p.category,
                    p.price,
                    p.quantity,
                    p.unit,
                    p.status,
                    u.id AS farmer_id,
                    u.full_name AS farmer_name,
                    u.location AS farmer_location
                FROM public.products p
                LEFT JOIN public.users u ON u.id = p.user_id
                WHERE p.product_id = CAST(:product_id AS uuid)
                  AND LOWER(COALESCE(p.status, '')) IN ('available', 'approved', 'active', 'published')
                LIMIT 1
                """
            ),
            {"product_id": product_id},
        ).mappings().first()
        return dict(row) if row else None
    except Exception as exc:
        logger.exception("[USSD] Failed to fetch customer product detail: %s", exc)
        return None


def customer_cart_snapshot(customer_id: str) -> dict[str, Any]:
    try:
        customer_uuid = uuid.UUID(customer_id)
    except Exception:
        return {"items": [], "item_count": 0, "subtotal": Decimal("0.00")}

    items: list[CartItem] = (
        db.session.query(CartItem)
        .filter(CartItem.user_id == customer_uuid)
        .order_by(CartItem.created_at.desc())
        .all()
    )

    rows: list[dict[str, Any]] = []
    subtotal = Decimal("0.00")

    for item in items:
        product = getattr(item, "product", None)
        if product is None:
            continue

        product_name = _safe_str(getattr(product, "product_name", None) or getattr(product, "name", None), "Product")
        unit = _safe_str(getattr(product, "unit", None), "each")
        price = _decimal_or_zero(getattr(product, "price", 0))
        qty = _decimal_or_zero(getattr(item, "qty", 0))
        line_total = (price * qty).quantize(Decimal("0.01"))
        subtotal = subtotal + line_total

        rows.append(
            {
                "cart_item_id": str(getattr(item, "id")),
                "product_id": str(getattr(item, "product_id")),
                "product_name": product_name,
                "qty": qty,
                "unit": unit,
                "unit_price": price.quantize(Decimal("0.01")),
                "line_total": line_total,
                "stock_qty": Decimal(str(getattr(product, "quantity", 0) or 0)),
                "farmer_id": str(getattr(product, "user_id", "") or ""),
            }
        )

    return {
        "items": rows,
        "item_count": len(rows),
        "subtotal": subtotal.quantize(Decimal("0.01")),
    }


def customer_cart_qty_for_product(customer_id: str, product_id: str) -> Decimal:
    snapshot = customer_cart_snapshot(customer_id)
    for row in cast(list[dict[str, Any]], snapshot.get("items") or []):
        if _safe_str(row.get("product_id")) == _safe_str(product_id):
            try:
                return Decimal(str(row.get("qty") or 0))
            except Exception:
                return Decimal("0")
    return Decimal("0")


def customer_add_to_cart(*, customer: User, product_id: str, qty: Decimal) -> tuple[bool, str]:
    qty = qty.quantize(Decimal("0.001"))
    if qty <= 0:
        return False, "Quantity must be greater than zero."

    detail = customer_product_detail(product_id)
    if not detail:
        return False, "Product not found or not available."

    try:
        customer_uuid = uuid.UUID(str(getattr(customer, "id")))
        product_uuid = uuid.UUID(product_id)
    except Exception:
        return False, "Invalid product."

    available_qty = _decimal_or_zero(detail.get("quantity"))
    existing = db.session.query(CartItem).filter(CartItem.user_id == customer_uuid, CartItem.product_id == product_uuid).first()
    current_qty = _decimal_or_zero(getattr(existing, "qty", 0)) if existing else Decimal("0")
    next_qty = (current_qty + qty).quantize(Decimal("0.001"))

    if available_qty > 0 and next_qty > available_qty:
        return False, f"Only {available_qty.normalize()} { _safe_str(detail.get('unit'), 'each') } available."

    try:
        if existing is None:
            distinct_count = db.session.query(CartItem).filter(CartItem.user_id == customer_uuid).count()
            if distinct_count >= 50:
                return False, "Cart limit reached."
            existing = CartItem()
            existing.user_id = customer_uuid
            existing.product_id = product_uuid
            existing.qty = next_qty
            db.session.add(existing)
        else:
            existing.qty = next_qty
        db.session.commit()
        return True, f"Added {_short_text(detail.get('product_name'), 16)} to cart."
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to add item to cart: %s", exc)
        return False, "Could not add item to cart."


def customer_update_cart_item_qty(*, customer: User, cart_item_id: str, qty: Decimal) -> tuple[bool, str]:
    try:
        customer_uuid = uuid.UUID(str(getattr(customer, "id")))
        cart_item_uuid = uuid.UUID(cart_item_id)
    except Exception:
        return False, "Invalid cart item."

    item = db.session.query(CartItem).filter(CartItem.user_id == customer_uuid, CartItem.id == cart_item_uuid).first()
    if item is None:
        return False, "Cart item not found."

    if qty <= 0:
        try:
            db.session.delete(item)
            db.session.commit()
            return True, "Item removed from cart."
        except Exception as exc:
            db.session.rollback()
            logger.exception("[USSD] Failed to remove cart item via qty update: %s", exc)
            return False, "Could not update cart."

    product = getattr(item, "product", None)
    stock_qty = Decimal(str(getattr(product, "quantity", 0) or 0)) if product is not None else Decimal("0")
    if stock_qty > 0 and qty > stock_qty:
        unit = _safe_str(getattr(product, "unit", None), "each") if product is not None else "each"
        return False, f"Only {stock_qty.normalize()} {unit} available."

    try:
        item.qty = qty.quantize(Decimal("0.001"))
        db.session.commit()
        return True, "Cart updated."
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to update cart qty: %s", exc)
        return False, "Could not update cart."


def customer_remove_cart_item(*, customer: User, cart_item_id: str) -> tuple[bool, str]:
    try:
        customer_uuid = uuid.UUID(str(getattr(customer, "id")))
        cart_item_uuid = uuid.UUID(cart_item_id)
    except Exception:
        return False, "Invalid cart item."

    item = db.session.query(CartItem).filter(CartItem.user_id == customer_uuid, CartItem.id == cart_item_uuid).first()
    if item is None:
        return False, "Cart item not found."

    try:
        db.session.delete(item)
        db.session.commit()
        return True, "Item removed from cart."
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to remove cart item: %s", exc)
        return False, "Could not remove cart item."


def customer_clear_cart(customer: User) -> tuple[bool, str]:
    try:
        db.session.query(CartItem).filter(CartItem.user_id == getattr(customer, "id")).delete()
        db.session.commit()
        return True, "Cart cleared."
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to clear customer cart: %s", exc)
        return False, "Could not clear cart."


def _single_order_farmer_id(order_id: Any) -> Optional[str]:
    try:
        row = db.session.execute(
            text(
                """
                SELECT p.user_id AS farmer_id
                FROM public.order_items oi
                JOIN public.products p ON p.product_id = oi.product_id
                WHERE oi.order_id = CAST(:order_id AS uuid)
                GROUP BY p.user_id
                ORDER BY p.user_id
                LIMIT 1
                """
            ),
            {"order_id": str(order_id)},
        ).mappings().first()
        return _safe_str(row.get("farmer_id")) if row else None
    except Exception:
        db.session.rollback()
        return None


def _payment_method_label(payment_method: Any) -> str:
    raw = _safe_str(payment_method).lower()
    mapping = {
        "eft": "EFT / Bank",
        "bank": "EFT / Bank",
        "bank transfer": "EFT / Bank",
        "mobile_wallet": "Mobile Wallet",
        "wallet": "Mobile Wallet",
        "ewallet": "Mobile Wallet",
        "cash": "Cash",
        "cash_on_delivery": "Cash",
    }
    return mapping.get(raw, raw.replace("_", " ").title() or "-")


def _payment_supports_reference_confirmation(payment_method: Any) -> bool:
    return _safe_str(payment_method).lower() in {"eft", "bank", "bank transfer", "mobile_wallet", "wallet", "ewallet"}


def _payment_customer_status_label(
    payment_status: Any,
    *,
    payment_method: Any = "",
    has_reference_submission: bool = False,
) -> str:
    """
    Return one consistent customer-facing payment status label.

    WHY THIS HELPER EXISTS:
      • customer order details and payment info must use the same wording
      • USSD payment uses payment references, not file-proof language
      • the label should stay short and action-oriented on small screens

    STANDARD LABEL SET:
      • Unpaid
      • Payment ref submitted
      • Awaiting farmer confirmation
      • Paid
      • Needs correction
      • Refunded
    """
    raw = _safe_str(payment_status).lower()
    method_raw = _safe_str(payment_method).lower()
    supports_reference = _payment_supports_reference_confirmation(method_raw)

    if raw == "paid":
        return "Paid"
    if raw == "failed":
        return "Needs correction"
    if raw == "refunded":
        return "Refunded"

    if supports_reference:
        if has_reference_submission and raw == "pending":
            return "Awaiting farmer confirmation"
        if has_reference_submission:
            return "Payment ref submitted"
        return "Unpaid"

    return "Unpaid"


def _payment_order_code_prompt(*, has_reference_submission: bool = False) -> str:
    """Prompt for the order code before storing or updating a payment reference."""
    return "Update payment ref\nEnter order code\n0 Back" if has_reference_submission else "Submit payment ref\nEnter order code\n0 Back"


def _payment_reference_label(payment_method: Any) -> str:
    """Short, channel-neutral label for the submitted payment reference."""
    return "Wallet ref" if _safe_str(payment_method).lower() == "mobile_wallet" else "Payment ref"


def _payment_reference_action_label(payment_method: Any, *, has_reference_submission: bool = False) -> str:
    """Return a concise action label for the customer payment-confirmation menu."""
    if has_reference_submission:
        return "1 Update payment ref"
    return "1 Submit payment ref"


def _payment_reference_input_prompt(payment_method: Any) -> str:
    """Return a short USSD-safe prompt for the human-entered payment reference."""
    if _safe_str(payment_method).lower() == "mobile_wallet":
        return "Enter wallet ref\n0 Back"
    return "Enter bank ref\n0 Back"


def _normalize_order_code_input(value: Any) -> str:
    return _safe_str(value).upper().replace(" ", "")


def _customer_find_order_for_payment_reference(customer_id: str, order_code: str) -> Optional[dict[str, Any]]:
    normalized_code = _normalize_order_code_input(order_code)
    if not normalized_code:
        return None

    try:
        rows = db.session.execute(
            text(
                """
                SELECT
                    o.order_id,
                    o.order_date,
                    o.status,
                    o.order_total,
                    o.delivery_method,
                    COALESCE(p.status, 'unpaid') AS payment_status,
                    COALESCE(p.method, '-') AS payment_method,
                    COALESCE(p.reference, '') AS payment_reference,
                    p.payment_id
                FROM public.orders o
                LEFT JOIN LATERAL (
                    SELECT p1.payment_id, p1.status, p1.method, p1.reference
                    FROM public.payments p1
                    WHERE p1.order_id = o.order_id
                    ORDER BY COALESCE(p1.updated_at, p1.created_at) DESC
                    LIMIT 1
                ) p ON true
                WHERE o.buyer_id = CAST(:customer_id AS uuid)
                ORDER BY o.order_date DESC
                LIMIT 50
                """
            ),
            {"customer_id": customer_id},
        ).mappings().all()
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to resolve order code for payment confirmation: %s", exc)
        return None

    for row in rows or []:
        candidate = dict(row)
        if _short_public_code("O", candidate.get("order_id")) == normalized_code:
            return candidate
    return None


def _notify_farmer_of_ussd_payment_reference(
    *,
    customer: User,
    order_row: dict[str, Any],
    payment_method: str,
    payment_reference: str,
) -> None:
    """Best-effort farmer alert for a USSD payment reference submission."""
    order_id = _safe_str(order_row.get("order_id"))
    if not order_id:
        return

    farmer_id = _safe_str(order_row.get("farmer_id"))
    payment_id = order_row.get("payment_id")

    try:
        payment = db.session.get(Payment, int(payment_id)) if payment_id is not None else None
    except Exception:
        payment = None

    if payment is not None and getattr(payment, "user_id", None) is not None:
        farmer_id = str(getattr(payment, "user_id"))
    if not farmer_id:
        farmer_id = _single_order_farmer_id(order_id)
    if not farmer_id or farmer_id == str(getattr(customer, "id", "")):
        return

    if _table_exists("notifications"):
        try:
            db.session.execute(
                text(
                    """
                    INSERT INTO public.notifications (
                        notification_id, user_id, actor_user_id, order_id,
                        notification_type, title, message, event_key,
                        data_json, is_read, created_at, updated_at
                    ) VALUES (
                        CAST(:notification_id AS uuid), CAST(:user_id AS uuid), CAST(:actor_user_id AS uuid), CAST(:order_id AS uuid),
                        :notification_type, :title, :message, :event_key,
                        CAST(:data_json AS jsonb), false, :created_at, :updated_at
                    )
                    ON CONFLICT (event_key) DO UPDATE SET
                        title = EXCLUDED.title,
                        message = EXCLUDED.message,
                        data_json = EXCLUDED.data_json,
                        updated_at = EXCLUDED.updated_at,
                        is_read = false
                    """
                ),
                {
                    "notification_id": str(uuid.uuid4()),
                    "user_id": farmer_id,
                    "actor_user_id": str(getattr(customer, "id", "")) or None,
                    "order_id": order_id,
                    "notification_type": "payment_submitted",
                    "title": "Payment confirmation submitted",
                    "message": (
                        f"{_first_name(customer)} submitted a {_payment_method_label(payment_method)} reference "
                        f"for order {_short_public_code('O', order_id)}. Review it and confirm payment."
                    ),
                    "event_key": f"ussd_payment_confirmation:{order_id}:{farmer_id}:{payment_reference}",
                    "data_json": json.dumps(
                        {
                            "category": "orders",
                            "source": "ussd",
                            "payment_confirmation_mode": "reference_only",
                            "payment_confirmation_source": "ussd",
                            "payment_reference": payment_reference,
                            "payment_method": payment_method,
                            "oid": order_id,
                            "order_code": _short_public_code("O", order_id),
                            "buyer": _safe_str(getattr(customer, "full_name", ""), "Customer"),
                            "buyer_name": _safe_str(getattr(customer, "full_name", ""), "Customer"),
                            "payment_proof_url": "",
                            "payment_proof_name": "",
                        },
                        ensure_ascii=False,
                    ),
                    "created_at": _utcnow(),
                    "updated_at": _utcnow(),
                },
            )
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            logger.warning("[USSD] Failed to notify farmer of payment reference: %s", exc)


def customer_confirm_payment_reference(*, customer: User, order_code: str, payment_reference: str) -> tuple[bool, str]:
    order_row = _customer_find_order_for_payment_reference(str(getattr(customer, "id")), order_code)
    if not order_row:
        return False, "Order code not found."

    payment_method = _safe_str(order_row.get("payment_method"), "-")
    if not _payment_supports_reference_confirmation(payment_method):
        return False, "This order uses cash. No payment ref needed."

    payment_id = order_row.get("payment_id")
    if payment_id is None:
        return False, "No payment record found for this order."

    reference_value = _safe_str(payment_reference)[:120]
    if len(reference_value) < 4:
        return False, "Payment ref is too short."

    try:
        payment = db.session.get(Payment, int(payment_id))
    except Exception:
        payment = None
    if payment is None:
        return False, "Payment record not found."

    try:
        payment.reference = reference_value
        payment.status = "pending"
        payment.updated_at = _utcnow()
        db.session.add(payment)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Failed to store payment reference: %s", exc)
        return False, "Could not save payment ref."

    _notify_farmer_of_ussd_payment_reference(
        customer=customer,
        order_row=order_row,
        payment_method=payment_method,
        payment_reference=reference_value,
    )

    return True, "Payment ref submitted. Awaiting farmer confirmation."


def customer_payment_info_payload(customer_id: str, *, order_id: str = "") -> dict[str, Any]:
    """
    Build a short payment-info summary plus an optional detail page.

    ORDER-SCOPED UX:
      • when the customer opens Payment Info from Order Details, the payment
        screen must stay scoped to that exact order instead of jumping to the
        most recent order overall
      • when no order is supplied, we gracefully fall back to the latest order
      • digital payments become directly completable from the selected order
        once the farmer marks the quote ready for payment
    """
    detail: Optional[dict[str, Any]] = None
    normalized_order_id = _safe_str(order_id)
    if normalized_order_id:
        detail = customer_order_detail(customer_id, normalized_order_id)

    if detail is None:
        orders = customer_latest_orders(customer_id, limit=1, offset=0)
        if not orders:
            return {
                "summary_lines": ["Payment Info", "No orders yet."],
                "detail_lines": [],
                "has_more": False,
                "can_confirm": False,
                "order_id": "",
                "order_code": "",
            }
        latest_order_id = _safe_str(orders[0].get("order_id"))
        detail = customer_order_detail(customer_id, latest_order_id) if latest_order_id else None
        if detail is None:
            detail = orders[0]

    row = detail
    order_id_value = _safe_str(row.get("order_id"))
    order_code = _short_public_code("O", order_id_value)
    payment_status = _safe_str(row.get("payment_status"), "unpaid")
    payment_method = _safe_str(row.get("payment_method"), "-")
    delivery_method = _safe_str(row.get("delivery_method"), "delivery")
    delivery_fee_status = _safe_str(row.get("delivery_fee_status"), "")
    quote_ready = _customer_checkout_stage_label(delivery_method, delivery_fee_status) == "Ready for payment"
    method_label = _payment_method_label(payment_method)
    financials = _quote_financials(row.get("order_total"), row.get("delivery_fee"))
    display_total = financials["grand_total"] if quote_ready else financials["products_subtotal"]
    reference = _safe_str(row.get("payment_reference"))
    has_reference_submission = bool(reference) and reference != order_code
    supports_reference = _payment_supports_reference_confirmation(payment_method)
    status_label = _payment_customer_status_label(
        payment_status,
        payment_method=payment_method,
        has_reference_submission=has_reference_submission and supports_reference,
    )
    stage_label = _customer_checkout_stage_label(delivery_method, delivery_fee_status)
    farmer_name = _safe_str(row.get("farmer_name"), "Farmer")
    farmer_location = _safe_str(row.get("farmer_location"), "Not set")
    delivery_address = _safe_str(row.get("delivery_address"), "")
    delivery_status = _delivery_status_label(row.get("delivery_status"))

    if not supports_reference:
        if quote_ready:
            status_label = "Pay cash on delivery" if delivery_method == "delivery" else "Pay cash on pickup"
        else:
            status_label = "Waiting for farmer quote"

    summary_lines = [
        "Payment Info",
        f"Order: {order_code}",
        f"Stage: {_short_text(stage_label, 24)}",
        f"Total: {_money(display_total)}",
        f"Status: {_short_text(status_label, 24)}",
    ]

    if not quote_ready:
        summary_lines.append("Next: wait for farmer")
    elif payment_method.lower() == "mobile_wallet":
        if status_label == "Awaiting farmer confirmation":
            summary_lines.append("Next: wait for farmer")
        elif status_label == "Needs correction":
            summary_lines.append("Next: update wallet ref")
        else:
            summary_lines.append("Next: submit wallet ref")
    elif supports_reference:
        if status_label == "Awaiting farmer confirmation":
            summary_lines.append("Next: wait for farmer")
        elif status_label == "Needs correction":
            summary_lines.append("Next: update payment ref")
        else:
            summary_lines.append("Next: submit payment ref")
    else:
        summary_lines.append("Next: pay cash when ready")

    detail_lines: list[str] = [
        "Payment Detail",
        f"Order: {order_code}",
        f"Farmer: {_short_text(farmer_name, 18, 'Farmer')}",
        f"Location: {_short_text(farmer_location, 18, 'Not set')}",
        f"Method: {_short_text(method_label, 16)}",
        f"Delivery: {_short_text(delivery_method.title(), 16)}",
        f"Del status: {_short_text(delivery_status, 16)}",
    ]
    if delivery_method == "delivery" and delivery_address:
        detail_lines.append(f"Addr: {_short_text(delivery_address, 18)}")

    if quote_ready:
        detail_lines.extend(
            [
                f"Products: {_money(financials['products_subtotal'])}",
                f"Delivery fee: {_money(financials['delivery_fee'])}",
                f"VAT: {_money(financials['vat_amount'])}",
                f"Grand total: {_money(financials['grand_total'])}",
            ]
        )
    else:
        detail_lines.extend(
            [
                f"Products: {_money(financials['products_subtotal'])}",
                "Delivery fee: waiting",
                "VAT: after quote",
            ]
        )

    if has_reference_submission:
        detail_lines.append(f"{_payment_reference_label(payment_method)}: {_short_text(reference, 18)}")
    elif supports_reference and quote_ready:
        detail_lines.append(f"Order ref: {order_code}")

    farmer_id = _single_order_farmer_id(order_id_value)
    farmer_row = _farmer_payment_profile_row(farmer_id) if farmer_id else None
    if quote_ready and farmer_row and _safe_str(payment_method).lower() in {"eft", "bank", "bank transfer"}:
        detail_lines.append(f"Bank: {_short_text(farmer_row.get('bank_name'), 18)}")
        detail_lines.append(f"Acc: {_masked_account_number(farmer_row.get('account_number'))}")
        detail_lines.append(f"Branch: {_short_text(farmer_row.get('branch_code'), 14)}")

    has_more = len(detail_lines) > 5
    can_confirm = bool(quote_ready and supports_reference and payment_status in {"unpaid", "failed", "pending"})

    return {
        "summary_lines": summary_lines,
        "detail_lines": detail_lines,
        "has_more": has_more,
        "can_confirm": can_confirm,
        "order_id": order_id_value,
        "order_code": order_code,
        "payment_method": payment_method,
        "payment_status": payment_status,
        "has_reference_submission": has_reference_submission,
        "payment_reference": reference,
        "status_label": status_label,
        "quote_ready": quote_ready,
        "supports_reference": supports_reference,
    }

def customer_checkout_from_cart(
    *,
    customer: User,
    delivery_method: str,
    payment_method: str,
    delivery_address: str = "",
) -> tuple[bool, str]:
    """
    Create one order per farmer from the current cart.

    PAYMENT UX:
      • Cash orders do not require any payment reference submission.
      • EFT / Mobile Wallet orders are created as unpaid first.
      • The customer later opens Payment Info on USSD and submits the bank or
        wallet payment reference for farmer verification.
    """
    snapshot = customer_cart_snapshot(str(getattr(customer, "id")))
    items = cast(list[dict[str, Any]], snapshot.get("items") or [])
    if not items:
        return False, "Your cart is empty."

    by_farmer: dict[str, list[dict[str, Any]]] = {}
    for row in items:
        farmer_id = _safe_str(row.get("farmer_id"))
        product_id = _safe_str(row.get("product_id"))
        if not farmer_id or not product_id:
            continue
        by_farmer.setdefault(farmer_id, []).append(row)

    if not by_farmer:
        return False, "Cart items are invalid. Please rebuild the cart."

    created_codes: list[str] = []
    checkout_ready = delivery_method == "pickup"
    payment_method_key = _safe_str(payment_method).lower()
    payment_method_db = {
        "eft": "eft",
        "mobile_wallet": "mobile_wallet",
        "cash": "cash_on_delivery",
    }.get(payment_method_key, "cash_on_delivery")
    payment_status = "pending" if payment_method_key == "cash" else "unpaid"
    delivery_fee_status = "awaiting_customer_payment" if checkout_ready else "pending_quote"
    customer_phone = normalize_phone_number(getattr(customer, "phone", None))

    try:
        for farmer_id, rows in by_farmer.items():
            order = Order()
            order.buyer_id = getattr(customer, "id")
            order.status = "pending"
            order.delivery_method = delivery_method
            order.delivery_address = delivery_address or None
            order.delivery_status = "pending"
            order.delivery_fee = Decimal("0.00")
            order.delivery_fee_status = delivery_fee_status
            order.order_date = _utcnow()

            subtotal = Decimal("0.00")
            for row in rows:
                line_total_value = _decimal_or_zero(row.get("line_total"))
                subtotal = subtotal + line_total_value
            order.order_total = subtotal.quantize(Decimal("0.01"))

            db.session.add(order)
            db.session.flush()

            order_id = getattr(order, "order_id", None) or getattr(order, "id", None)
            if order_id is None:
                raise RuntimeError("Order ID was not generated")

            order_code = _short_public_code("O", order_id)

            for row in rows:
                item = OrderItem()
                item.order_id = order_id
                item.product_id = uuid.UUID(_safe_str(row.get("product_id")))
                item.quantity = Decimal(str(row.get("qty") or 0)).quantize(Decimal("0.001"))
                item.unit_price = Decimal(str(row.get("unit_price") or 0)).quantize(Decimal("0.01"))
                item.line_total = Decimal(str(row.get("line_total") or 0)).quantize(Decimal("0.01"))
                item.unit = _safe_str(row.get("unit"), "each")
                item.fulfillment_status = "pending"
                item.delivery_status = "pending"
                db.session.add(item)

            payment = Payment()
            payment.order_id = order_id
            payment.user_id = uuid.UUID(farmer_id)
            payment.amount = subtotal.quantize(Decimal("0.01"))
            payment.status = payment_status
            payment.method = payment_method_db
            payment.reference = order_code
            payment.proof_url = None
            db.session.add(payment)

            created_codes.append(order_code)

            farmer_row = _farmer_payment_profile_row(farmer_id)
            if customer_phone:
                if payment_method_key == "eft" and checkout_ready and farmer_row:
                    bank_name = _safe_str(farmer_row.get("bank_name"), "Bank")
                    account_name = _short_text(farmer_row.get("account_name"), 18, "Account")
                    account_number = _safe_str(farmer_row.get("account_number"), "-")
                    branch_code = _safe_str(farmer_row.get("branch_code"), "-")
                    sms = (
                        f"AgroConnect {order_code}: EFT ready. Total {_money(subtotal)}. "
                        f"Bank {bank_name}. Acc {account_name}/{account_number}. "
                        f"Branch {branch_code}. Ref {order_code}. After payment, use Payment Info to submit your ref."
                    )
                    _send_action_sms(
                        phone_number=customer_phone,
                        message=sms,
                        user_id=str(getattr(customer, "id")),
                        template_name="ussd_checkout_ready",
                    )
                elif payment_method_key == "mobile_wallet" and checkout_ready:
                    _send_action_sms(
                        phone_number=customer_phone,
                        message=(
                            f"AgroConnect {order_code}: Mobile wallet selected. Total {_money(subtotal)}. "
                            f"After payment, use Payment Info to submit your wallet ref."
                        ),
                        user_id=str(getattr(customer, "id")),
                        template_name="ussd_checkout_ready",
                    )
                else:
                    if payment_method_key == "cash":
                        note = "Cash selected. Pay on pickup or delivery when the farmer confirms."
                    elif payment_method_key == "mobile_wallet":
                        note = "Order created. Wait for delivery fee update, then pay by mobile wallet and confirm on USSD."
                    else:
                        note = "Order created. Wait for delivery fee update, then pay by bank and confirm on USSD."
                    _send_action_sms(
                        phone_number=customer_phone,
                        message=f"AgroConnect {order_code}: {note}",
                        user_id=str(getattr(customer, "id")),
                        template_name="ussd_checkout_created",
                    )

        db.session.query(CartItem).filter(CartItem.user_id == getattr(customer, "id")).delete()
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Customer checkout from cart failed: %s", exc)
        return False, "Could not complete checkout."

    if not created_codes:
        return False, "Could not create any orders from the cart."

    joined_codes = ", ".join(created_codes[:3])
    if len(created_codes) > 3:
        joined_codes += "..."

    if delivery_method == "delivery":
        if payment_method_key == "cash":
            return True, (
                f"Checkout placed. Orders: {joined_codes}. "
                "Farmers must set delivery fees first. Pay cash when delivery is confirmed."
            )
        if payment_method_key == "mobile_wallet":
            return True, (
                f"Checkout placed. Orders: {joined_codes}. "
                "Wait for the delivery fee, then pay by mobile wallet and submit your payment ref in Payment Info."
            )
        return True, (
            f"Checkout placed. Orders: {joined_codes}. "
            "Wait for the delivery fee, then pay by EFT and submit your payment ref in Payment Info."
        )

    if payment_method_key == "eft":
        return True, (
            f"Checkout placed. Orders: {joined_codes}. "
            "Pickup has no delivery fee. Bank details were sent by SMS. After paying, submit your payment ref in Payment Info."
        )

    if payment_method_key == "mobile_wallet":
        return True, (
            f"Checkout placed. Orders: {joined_codes}. "
            "Pickup has no delivery fee. Pay by mobile wallet, then submit your payment ref in Payment Info."
        )

    return True, (
        f"Checkout placed. Orders: {joined_codes}. "
        "Pay cash on pickup or delivery when the farmer confirms."
    )


def customer_category_summary(*, limit: int = 6) -> list[str]:
    rows = customer_category_rows(limit=limit)
    return [f"{_safe_str(row.get('category'))[:20]} ({row.get('item_count')})" for row in rows]



# ---------------------------------------------------------------------------
# SMS helper
# ---------------------------------------------------------------------------
def _send_action_sms(
    *,
    phone_number: str,
    message: str,
    user_id: Optional[str] = None,
    template_name: Optional[str] = None,
    context: Optional[dict[str, Any]] = None,
) -> None:
    provider = _safe_str(os.environ.get("SMS_PROVIDER"), "console").lower()
    if provider == "africastalking":
        send_sms_via_africastalking(
            to=phone_number,
            body=message,
            user_id=user_id,
            template_name=template_name,
            context=context,
        )
        return
    logger.info("[USSD SMS][CONSOLE] to=%s body=%s", phone_number, message)


# ---------------------------------------------------------------------------
# Menu builders / result views
# ---------------------------------------------------------------------------
def _welcome_menu() -> str:
    return "Welcome to AgroConnect\n1 Farmer\n2 Customer\n9 Help"


def _farmer_secure_menu() -> str:
    return (
        "Farmer Dashboard\n"
        "1 My products\n"
        "2 Add product\n"
        "3 My orders\n"
        "4 Payment refs\n"
        "5 Monthly sales\n"
        "6 Stock alerts\n"
        "7 Bank profile\n"
        "8 Help\n"
        "9 Logout\n"
        "0 Main menu"
    )


def _customer_secure_menu() -> str:
    return (
        "Customer Dashboard\n"
        "1 Search products\n"
        "2 Browse categories\n"
        "3 My cart\n"
        "4 My orders\n"
        "5 Payment info\n"
        "6 Help\n"
        "7 Logout\n"
        "0 Main menu"
    )


def _paginate_view_lines(
    lines: list[str],
    *,
    first_page_size: int = 5,
    next_page_size: int = 6,
) -> list[list[str]]:
    """
    Split long informational text into short USSD-friendly pages.

    WHY THIS EXISTS:
      • long help / payment / bank screens increase timeout risk
      • the first page should stay especially short
      • later pages can carry a little more detail
    """
    cleaned = [_safe_str(line) for line in lines if _safe_str(line)]
    if not cleaned:
        return [["No details available."]]

    pages: list[list[str]] = []
    index = 0
    page_size = max(1, int(first_page_size or 5))
    carry_size = max(1, int(next_page_size or 6))

    while index < len(cleaned):
        pages.append(cleaned[index : index + page_size])
        index += page_size
        page_size = carry_size

    return pages or [["No details available."]]



def _render_paged_view_message(pages: list[list[str]], index: int) -> str:
    safe_pages = pages or [["No details available."]]
    safe_index = max(0, min(index, len(safe_pages) - 1))
    lines = list(safe_pages[safe_index])
    if len(safe_pages) > 1 and safe_index < len(safe_pages) - 1:
        lines.append("1 More")
    if len(safe_pages) > 1 and safe_index > 0:
        lines.append("2 Prev")
    lines.append("0 Back")
    return "\n".join(lines)



def _set_result_view(
    session: dict[str, Any],
    *,
    state: str,
    message: str,
    back_state: Optional[str] = None,
    back_menu: Optional[str] = None,
) -> UssdResponse:
    data = dict(session.get("data") or {})
    data.pop("view_pages", None)
    data.pop("view_page_index", None)
    data["message"] = message
    if back_state is not None:
        data["back_state"] = back_state
    if back_menu is not None:
        data["back_menu"] = back_menu
    session["state"] = state
    session["data"] = data
    return ussd_continue(f"{message}\n0 Back")



def _set_paged_result_view(
    session: dict[str, Any],
    *,
    state: str,
    lines: list[str],
    back_state: Optional[str] = None,
    back_menu: Optional[str] = None,
    first_page_size: int = 5,
    next_page_size: int = 6,
) -> UssdResponse:
    data = dict(session.get("data") or {})
    pages = _paginate_view_lines(lines, first_page_size=first_page_size, next_page_size=next_page_size)
    data["view_pages"] = pages
    data["view_page_index"] = 0
    data["message"] = "\n".join(pages[0])
    if back_state is not None:
        data["back_state"] = back_state
    if back_menu is not None:
        data["back_menu"] = back_menu
    session["state"] = state
    session["data"] = data
    return ussd_continue(_render_paged_view_message(pages, 0))



def _handle_backable_view(session: dict[str, Any], *, back_state: str, back_menu: str, user_input: str) -> UssdResponse:
    data = cast(dict[str, Any], session.get("data") or {})
    resolved_back_state = _safe_str(data.get("back_state"), back_state)
    resolved_back_menu = _safe_str(data.get("back_menu"), back_menu)
    pages = cast(list[list[str]], data.get("view_pages") or [])

    if pages:
        page_index = max(0, int(data.get("view_page_index", 0) or 0))
        if user_input == "1" and page_index < len(pages) - 1:
            data["view_page_index"] = page_index + 1
            session["data"] = data
            return ussd_continue(_render_paged_view_message(pages, page_index + 1))
        if user_input == "2" and page_index > 0:
            data["view_page_index"] = page_index - 1
            session["data"] = data
            return ussd_continue(_render_paged_view_message(pages, page_index - 1))
        if user_input == "0":
            session["state"] = resolved_back_state
            session["data"] = {
                key: value
                for key, value in data.items()
                if key not in {"message", "back_state", "back_menu", "view_pages", "view_page_index"}
            }
            return ussd_continue(resolved_back_menu)
        return ussd_continue(_render_paged_view_message(pages, page_index))

    message = _safe_str(data.get("message"), "No details available.")
    if user_input == "0":
        session["state"] = resolved_back_state
        session["data"] = {
            key: value
            for key, value in data.items()
            if key not in {"message", "back_state", "back_menu"}
        }
        return ussd_continue(resolved_back_menu)
    return ussd_continue(f"{message}\n0 Back")


def _authenticated_role(session: dict[str, Any]) -> Optional[int]:
    if not bool(session.get("is_authenticated")):
        return None
    user_id = _safe_str(session.get("user_id"))
    if not user_id:
        return None
    try:
        user = db.session.get(User, uuid.UUID(user_id))
    except Exception:
        user = None
    if user is None:
        return None
    return int(getattr(user, "role", 0) or 0)


# ---------------------------------------------------------------------------
# Authenticated user guards
# ---------------------------------------------------------------------------
def _require_authenticated_user(
    session: dict[str, Any],
    *,
    role_value: int,
    public_menu_text: str,
    public_state: str,
) -> tuple[Optional[User], Optional[UssdResponse]]:
    user_id = _safe_str(session.get("user_id"))
    if not bool(session.get("is_authenticated")) or not user_id:
        session["state"] = public_state
        return None, ussd_continue(f"Login required first.\n{public_menu_text}")

    try:
        user = db.session.get(User, uuid.UUID(user_id))
    except Exception:
        user = None

    if user is None or int(getattr(user, "role", 0) or 0) != int(role_value):
        session["is_authenticated"] = False
        session["user_id"] = None
        session["state"] = public_state
        return None, ussd_continue(f"{_role_name(role_value).capitalize()} account not found.\n{public_menu_text}")

    return user, None


def _require_authenticated_farmer(session: dict[str, Any]) -> tuple[Optional[User], Optional[UssdResponse]]:
    return _require_authenticated_user(
        session,
        role_value=ROLE_FARMER,
        public_menu_text=_public_farmer_menu(normalize_phone_number(session.get("phone_number"))),
        public_state=STATE_FARMER_MENU,
    )


def _require_authenticated_customer(session: dict[str, Any]) -> tuple[Optional[User], Optional[UssdResponse]]:
    return _require_authenticated_user(
        session,
        role_value=ROLE_CUSTOMER,
        public_menu_text=_public_customer_menu(normalize_phone_number(session.get("phone_number"))),
        public_state=STATE_CUSTOMER_MENU,
    )


# ---------------------------------------------------------------------------
# Root / public state handlers
# ---------------------------------------------------------------------------
def _handle_root(session: dict[str, Any], user_input: str) -> UssdResponse:
    if not user_input:
        return ussd_continue(_welcome_menu())

    authenticated_role = _authenticated_role(session)

    if user_input == "1":
        if authenticated_role == int(ROLE_FARMER):
            session["state"] = STATE_FARMER_SECURE_MENU
            try:
                farmer = db.session.get(User, uuid.UUID(_safe_str(session.get("user_id"))))
            except Exception:
                farmer = None
            if farmer is not None:
                return ussd_continue(f"Welcome {_first_name(cast(User, farmer))}\n{_farmer_secure_menu()}")
        session["state"] = STATE_FARMER_MENU
        return ussd_continue(_public_farmer_menu(normalize_phone_number(session.get("phone_number"))))

    if user_input == "2":
        if authenticated_role == int(ROLE_CUSTOMER):
            session["state"] = STATE_CUSTOMER_SECURE_MENU
            try:
                customer = db.session.get(User, uuid.UUID(_safe_str(session.get("user_id"))))
            except Exception:
                customer = None
            if customer is not None:
                return ussd_continue(f"Welcome {_first_name(cast(User, customer))}\n{_customer_secure_menu()}")
        session["state"] = STATE_CUSTOMER_MENU
        return ussd_continue(_public_customer_menu(normalize_phone_number(session.get("phone_number"))))

    if user_input == "9":
        return ussd_continue("Help\n1 Farmer services\n2 Customer services\n0 Back")

    return ussd_continue(_welcome_menu())


def _render_farmer_products_page(session: dict[str, Any], farmer: User, banner: str = "") -> UssdResponse:
    page_size = 5
    data = cast(dict[str, Any], session.get("data") or {})
    offset = int(data.get("products_offset", 0) or 0)
    search_term = _safe_str(data.get("product_search"))
    rows = farmer_manageable_products(
        str(getattr(farmer, "id")),
        limit=page_size,
        offset=offset,
        search_term=search_term,
    )

    if not rows and offset > 0:
        offset = max(0, offset - page_size)
        rows = farmer_manageable_products(
            str(getattr(farmer, "id")),
            limit=page_size,
            offset=offset,
            search_term=search_term,
        )

    data["products_offset"] = offset
    data["product_page_ids"] = [str(row.get("product_id")) for row in rows]
    session["data"] = data

    lines: list[str] = []
    if banner:
        lines.append(banner)
    lines.append("My Products")
    if search_term:
        lines.append(f"Find: {_short_text(search_term, 16)}")

    if not rows:
        lines.append("No products found.")
        lines.append("S Search")
        if search_term:
            lines.append("C Clear")
        lines.append("0 Back")
        return ussd_continue("\n".join(lines))

    for idx, row in enumerate(rows, start=1):
        name = _short_text(row.get("product_name"), 10, "Product")
        status_short = _product_status_short(row.get("status"))
        activity = _date_label(row.get("activity_at"))
        lines.append(f"{idx}. {name} {status_short} {activity}")
    if len(rows) == page_size:
        lines.append("N Next")
    if offset > 0:
        lines.append("P Prev")
    lines.append("S Search")
    if search_term:
        lines.append("C Clear")
    lines.append("0 Back")
    return ussd_continue("\n".join(lines))


def _selected_farmer_product(session: dict[str, Any], farmer: User) -> Optional[Product]:
    product_id = _safe_str(cast(dict[str, Any], session.get("data") or {}).get("selected_product_id"))
    if not product_id:
        return None
    return farmer_product_detail(str(getattr(farmer, "id")), product_id)


def _render_farmer_product_actions(session: dict[str, Any], farmer: User) -> UssdResponse:
    product = _selected_farmer_product(session, farmer)
    if product is None:
        session["state"] = STATE_FARMER_PRODUCTS_PAGE
        data = cast(dict[str, Any], session.get("data") or {})
        data.pop("selected_product_id", None)
        session["data"] = data
        return _render_farmer_products_page(session, farmer, banner="Product not found.")

    is_rejected = _safe_str(getattr(product, "status", "")).lower() == "rejected"
    lines = [
        f"Product {_short_public_code('P', getattr(product, 'product_id', None))}",
        _short_text(getattr(product, 'product_name', ''), 18, 'Product'),
        f"{_product_status_short(getattr(product, 'status', ''))} {_money(getattr(product, 'price', 0))}",
        "1 View summary",
        "2 Update product",
        "3 Delete product",
        "4 Demand insight",
    ]
    if is_rejected:
        lines.append("5 Rejection / appeal")
    lines.append("0 Back")
    return ussd_continue("\n".join(lines))


def _render_farmer_orders_page(session: dict[str, Any], farmer: User, banner: str = "") -> UssdResponse:
    page_size = 5
    data = cast(dict[str, Any], session.get("data") or {})
    offset = int(data.get("orders_offset", 0) or 0)
    search_term = _safe_str(data.get("order_search"))
    rows = farmer_latest_orders(
        str(getattr(farmer, "id")),
        limit=page_size,
        offset=offset,
        search_term=search_term,
    )

    if not rows and offset > 0:
        offset = max(0, offset - page_size)
        rows = farmer_latest_orders(
            str(getattr(farmer, "id")),
            limit=page_size,
            offset=offset,
            search_term=search_term,
        )

    data["orders_offset"] = offset
    data["order_page_ids"] = [str(row.get("order_id")) for row in rows]
    session["data"] = data

    lines: list[str] = []
    if banner:
        lines.append(banner)
    lines.append("My Orders")
    if search_term:
        lines.append(f"Find: {_short_text(search_term, 16)}")

    if not rows:
        lines.append("No orders found.")
        lines.append("S Search")
        if search_term:
            lines.append("C Clear")
        lines.append("0 Back")
        return ussd_continue("\n".join(lines))

    for idx, row in enumerate(rows, start=1):
        order_code = _short_public_code("O", row.get("order_id"))
        buyer_name = _short_text(row.get("buyer_name"), 7, "Buyer")
        payment_short = _short_text(row.get("payment_status"), 4, "unpd")
        lines.append(f"{idx}. {order_code} {buyer_name} {payment_short}")
    if len(rows) == page_size:
        lines.append("N Next")
    if offset > 0:
        lines.append("P Prev")
    lines.append("S Search")
    if search_term:
        lines.append("C Clear")
    lines.append("0 Back")
    return ussd_continue("\n".join(lines))


def _render_farmer_order_actions(session: dict[str, Any], farmer: User) -> UssdResponse:
    """Compact farmer order hub with quote-management actions."""
    data = cast(dict[str, Any], session.get("data") or {})
    order_id = _safe_str(data.get("selected_order_id"))
    detail = farmer_order_detail(str(getattr(farmer, "id")), order_id) if order_id else None
    if not detail:
        session["state"] = STATE_FARMER_ORDERS_PAGE
        data.pop("selected_order_id", None)
        session["data"] = data
        return _render_farmer_orders_page(session, farmer, banner="Order not found.")

    financials = _quote_financials(detail.get("farmer_total"), detail.get("delivery_fee"))
    quote_ready = _delivery_quote_is_ready(detail.get("delivery_fee_status"))
    lines = [
        f"Order {_short_public_code('O', detail.get('order_id'))}",
        f"{_short_text(detail.get('buyer_name'), 12, 'Buyer')} {_date_label(detail.get('order_date'))}",
        f"Pay: {_short_text(detail.get('payment_status'), 6)} {_short_text(_payment_method_label(detail.get('payment_method')), 10)}",
        f"Fee: {_money(financials['delivery_fee'])}",
        f"Quote: {'ready' if quote_ready else 'pending'}",
        "1 Payment details",
        "2 Update delivery",
        "3 Set delivery fee",
        "4 Ready for payment",
        "0 Back",
    ]
    return ussd_continue("\n".join(lines))


def _render_farmer_payment_confirmations_page(session: dict[str, Any], farmer: User, banner: str = "") -> UssdResponse:
    page_size = 5
    data = cast(dict[str, Any], session.get("data") or {})
    offset = int(data.get("payment_confirmations_offset", 0) or 0)
    rows = farmer_orders_awaiting_payment_confirmation(str(getattr(farmer, "id")), limit=page_size, offset=offset)

    if not rows and offset > 0:
        offset = max(0, offset - page_size)
        rows = farmer_orders_awaiting_payment_confirmation(str(getattr(farmer, "id")), limit=page_size, offset=offset)

    data["payment_confirmations_offset"] = offset
    data["payment_confirmation_page_ids"] = [str(row.get("order_id")) for row in rows]
    session["data"] = data

    lines: list[str] = []
    if banner:
        lines.append(banner)
    lines.append("Payment Refs")

    if not rows:
        lines.append("No pending refs.")
        lines.append("0 Back")
        return ussd_continue("\n".join(lines))

    for idx, row in enumerate(rows, start=1):
        order_code = _short_public_code("O", row.get("order_id"))
        buyer_name = _short_text(row.get("buyer_name"), 7, "Buyer")
        method_short = _short_text(_payment_method_label(row.get("payment_method")), 6, "Pay")
        lines.append(f"{idx}. {order_code} {buyer_name} {method_short}")
    if len(rows) == page_size:
        lines.append("N Next")
    if offset > 0:
        lines.append("P Prev")
    lines.append("0 Back")
    return ussd_continue("\n".join(lines))


def _render_farmer_payment_confirmation_actions(session: dict[str, Any], farmer: User, banner: str = "") -> UssdResponse:
    data = cast(dict[str, Any], session.get("data") or {})
    order_id = _safe_str(data.get("selected_payment_confirmation_order_id"))
    detail = farmer_payment_confirmation_detail(str(getattr(farmer, "id")), order_id) if order_id else None
    if not detail:
        session["state"] = STATE_FARMER_PAYMENT_CONFIRMATIONS_PAGE
        data.pop("selected_payment_confirmation_order_id", None)
        session["data"] = data
        return _render_farmer_payment_confirmations_page(session, farmer, banner="Payment confirmation not found.")

    reference_label = _payment_reference_label(detail.get("payment_method"))
    lines: list[str] = []
    if banner:
        lines.append(banner)
    lines.extend(
        [
            "Payment Review",
            f"Order {_short_public_code('O', detail.get('order_id'))}",
            f"Buyer: {_short_text(detail.get('buyer_name'), 12, 'Buyer')}",
            f"Method: {_short_text(_payment_method_label(detail.get('payment_method')), 16, '-')}",
            f"Amount: {_money(detail.get('order_total'))}",
            f"{reference_label}: {_short_text(detail.get('payment_reference'), 16, '-')}",
            f"Sent: {_date_time_label(detail.get('payment_timestamp'))}",
            "1 Confirm paid",
            "2 Reject ref",
            "0 Back",
        ]
    )
    return ussd_continue("\n".join(lines))


def _render_farmer_help_menu(session: dict[str, Any], farmer: User) -> UssdResponse:
    orders_sms = "ON" if _farmer_orders_sms_enabled(str(getattr(farmer, "id"))) else "OFF"
    return ussd_continue(
        "Farmer Help\n"
        f"Orders SMS: {orders_sms}\n"
        "1 Products help\n"
        "2 Orders help\n"
        "3 Sales & bank help\n"
        "0 Back"
    )


def _farmer_help_topic_text(topic: str) -> str:
    if topic == "products":
        return (
            "Products Help\n"
            "1 My products: view your list.\n"
            "Use S to search, N for next,\n"
            "P for previous, C to clear.\n"
            "Open a product to update,\n"
            "delete, demand, or appeal."
        )
    if topic == "orders":
        return (
            "Orders Help\n"
            "3 My orders: recent orders first.\n"
            "4 Payment refs: confirm or\n"
            "reject submitted payment refs.\n"
            "Use S to search orders.\n"
            "Open an order for payment\n"
            "details or delivery update."
        )
    return (
        "Sales & Bank Help\n"
        "5 Monthly sales: paid sales.\n"
        "6 Stock alerts: low stock check.\n"
        "7 Bank profile: view or edit\n"
        "bank, account, branch, ref."
    )


def _handle_farmer_menu(session: dict[str, Any], user_input: str) -> UssdResponse:
    phone_number = normalize_phone_number(session.get("phone_number"))
    menu_text = _public_farmer_menu(phone_number)
    already_active = _has_ussd_pin_for_phone(phone_number) and _find_user_by_phone(phone_number, role=ROLE_FARMER) is not None

    if not user_input:
        return ussd_continue(menu_text)

    if user_input == "0":
        session["state"] = STATE_ROOT
        return ussd_continue(_welcome_menu())

    if already_active:
        if user_input == "1":
            session["state"] = STATE_FARMER_LOGIN_PIN
            session["data"] = {}
            return ussd_continue("Login\nEnter your 4-digit PIN")
        if user_input == "2":
            existing = _find_user_by_phone(phone_number, role=ROLE_FARMER)
            if existing is None:
                return ussd_continue(menu_text)
            session["state"] = STATE_FARMER_REGISTER_PIN
            session["data"] = {
                "existing_activation": True,
                "full_name": _safe_str(getattr(existing, "full_name", "")),
                "location": _safe_str(getattr(existing, "location", "")),
            }
            return ussd_continue("Reset PIN\nSet new 4-digit USSD PIN")
        if user_input == "3":
            return ussd_continue("Farmer Help\n1 Login - open dashboard.\n2 Reset PIN - change PIN.\n3 Help - menu guidance.\n0 Back")
        return ussd_continue(menu_text)

    if user_input == "1":
        existing = _find_user_by_phone(phone_number)
        if existing is not None:
            existing_role = int(getattr(existing, "role", 0) or 0)
            if existing_role != int(ROLE_FARMER):
                return ussd_end("This phone number already belongs to a different account type.")
            session["state"] = STATE_FARMER_REGISTER_PIN
            session["data"] = {
                "existing_activation": True,
                "full_name": _safe_str(getattr(existing, "full_name", "")),
                "location": _safe_str(getattr(existing, "location", "")),
            }
            return ussd_continue("Farmer account found.\nSet 4-digit USSD PIN")
        session["state"] = STATE_FARMER_REGISTER_NAME
        session["data"] = {"existing_activation": False}
        return ussd_continue("Register / Activate USSD\nEnter full name")

    if user_input == "2":
        session["state"] = STATE_FARMER_LOGIN_PIN
        session["data"] = {}
        return ussd_continue("Login\nEnter your 4-digit PIN")

    if user_input == "3":
        return ussd_continue("Farmer Help\nRegister once, then login with PIN.\n0 Back")

    return ussd_continue(menu_text)


def _handle_farmer_register_name(session: dict[str, Any], user_input: str) -> UssdResponse:
    if not user_input:
        return ussd_continue("Register / Activate USSD\nEnter full name")
    if user_input == "0":
        session["state"] = STATE_FARMER_MENU
        session["data"] = {}
        return ussd_continue(_public_farmer_menu(normalize_phone_number(session.get("phone_number"))))

    data = {**(session.get("data") or {}), "full_name": user_input[:200]}
    session["data"] = data
    if bool(data.get("existing_activation")):
        session["state"] = STATE_FARMER_REGISTER_PIN
        return ussd_continue("Set 4-digit USSD PIN")

    session["state"] = STATE_FARMER_REGISTER_EMAIL
    return ussd_continue("Enter email for web login")


def _handle_farmer_register_email(session: dict[str, Any], user_input: str) -> UssdResponse:
    if not user_input:
        return ussd_continue("Enter email for web login")
    if user_input == "0":
        session["state"] = STATE_FARMER_REGISTER_NAME
        return ussd_continue("Register / Activate USSD\nEnter full name")

    email_value = _normalize_email(user_input)
    if not _email_is_valid(email_value):
        return ussd_continue("Valid email required\nEnter email for web login")

    existing_email = db.session.execute(select(User).where(User.email == email_value)).scalar_one_or_none()
    if existing_email is not None:
        return ussd_continue("Email already registered\nEnter another email")

    session["data"] = {**(session.get("data") or {}), "email": email_value}
    session["state"] = STATE_FARMER_REGISTER_WEB_PASSWORD
    return ussd_continue(_registration_password_prompt())


def _handle_farmer_register_web_password(session: dict[str, Any], user_input: str) -> UssdResponse:
    if not user_input:
        return ussd_continue(_registration_password_prompt())
    if user_input == "0":
        session["state"] = STATE_FARMER_REGISTER_EMAIL
        return ussd_continue("Enter email for web login")

    password_error = _web_password_validation_error(user_input)
    if password_error:
        return ussd_continue(f"{password_error}\n6-12 chars, no * or #")

    session["data"] = {**(session.get("data") or {}), "web_password": user_input}
    session["state"] = STATE_FARMER_REGISTER_WEB_PASSWORD_CONFIRM
    return ussd_continue("Retype web password")


def _handle_farmer_register_web_password_confirm(session: dict[str, Any], user_input: str) -> UssdResponse:
    data = cast(dict[str, Any], session.get("data") or {})
    if not user_input:
        return ussd_continue("Retype web password")
    if user_input == "0":
        session["state"] = STATE_FARMER_REGISTER_WEB_PASSWORD
        return ussd_continue(_registration_password_prompt())

    first_password = _safe_str(data.get("web_password"))
    if user_input != first_password:
        data.pop("web_password", None)
        session["data"] = data
        session["state"] = STATE_FARMER_REGISTER_WEB_PASSWORD
        return ussd_continue("Passwords do not match\nSet web password again")

    session["state"] = STATE_FARMER_REGISTER_PIN
    return ussd_continue("Set 4-digit USSD PIN")


def _handle_farmer_register_pin(session: dict[str, Any], user_input: str) -> UssdResponse:
    data = cast(dict[str, Any], session.get("data") or {})
    existing = bool(data.get("existing_activation"))
    prompt = "Set new 4-digit USSD PIN" if existing else "Set 4-digit USSD PIN"
    if not user_input:
        return ussd_continue(prompt)
    if user_input == "0":
        if existing:
            session["state"] = STATE_FARMER_MENU
            session["data"] = {}
            return ussd_continue(_public_farmer_menu(normalize_phone_number(session.get("phone_number"))))
        session["state"] = STATE_FARMER_REGISTER_WEB_PASSWORD_CONFIRM
        return ussd_continue("Retype web password")

    pin = _safe_str(user_input)
    if not _pin_is_valid(pin):
        return ussd_continue("PIN must be exactly 4 digits. Enter 4-digit PIN")

    full_name = _safe_str(data.get("full_name"))
    email = _normalize_email(data.get("email"))
    web_password = _safe_str(data.get("web_password"))
    phone_number = normalize_phone_number(session.get("phone_number"))

    ok, farmer, message = activate_or_register_ussd_user(
        phone_number=phone_number,
        role_value=ROLE_FARMER,
        full_name=full_name,
        email=email,
        web_password=web_password,
        pin=pin,
    )
    if not ok or farmer is None:
        if not existing and message in {"Email address is already registered.", "Valid email is required.", "Email is required."}:
            session["state"] = STATE_FARMER_REGISTER_EMAIL
            return ussd_continue(f"{message}\nEnter email for web login")
        if not existing and message in {"Web password is required."}:
            session["state"] = STATE_FARMER_REGISTER_WEB_PASSWORD
            return ussd_continue("Web password required\nSet web password")
        session["state"] = STATE_FARMER_MENU
        session["data"] = {}
        return ussd_continue(f"{message}\n0 Back")

    session["is_authenticated"] = True
    session["user_id"] = str(getattr(farmer, "id"))
    session["state"] = STATE_FARMER_SECURE_MENU
    session["data"] = {}

    _touch_user_auth_timestamps(user_id=getattr(farmer, "id"), update_login=True)
    _clear_registration_drafts_for_phone(phone_number, session.get("service_code"))

    _send_action_sms(
        phone_number=phone_number,
        user_id=str(getattr(farmer, "id")),
        template_name="ussd_farmer_activation",
        context={"full_name": getattr(farmer, "full_name", ""), "email": getattr(farmer, "email", "")},
        message="AgroConnect: Your farmer web account and USSD access are ready. You are now logged in.",
    )

    banner = "USSD activated successfully." if existing else message
    return ussd_continue(f"{banner}\nWelcome {_first_name(farmer)}\n{_farmer_secure_menu()}")



def _handle_farmer_login_pin(session: dict[str, Any], user_input: str) -> UssdResponse:
    if not user_input:
        return ussd_continue("Login\nEnter your 4-digit PIN")
    if user_input == "0":
        session["state"] = STATE_FARMER_MENU
        return ussd_continue(_public_farmer_menu(normalize_phone_number(session.get("phone_number"))))

    pin = _safe_str(user_input)
    if not _pin_is_valid(pin):
        return ussd_continue("PIN must be exactly 4 digits. Enter your 4-digit PIN")

    phone_number = normalize_phone_number(session.get("phone_number"))
    ok, user_id, message = _verify_ussd_pin(phone_number, pin)
    if not ok or not user_id:
        return ussd_continue(message)

    farmer = db.session.get(User, uuid.UUID(user_id))
    if farmer is None or int(getattr(farmer, "role", 0) or 0) != int(ROLE_FARMER):
        return ussd_end("Farmer account not found for this phone number.")

    session["is_authenticated"] = True
    session["user_id"] = user_id
    session["state"] = STATE_FARMER_SECURE_MENU
    session["data"] = {}
    _clear_registration_drafts_for_phone(phone_number, session.get("service_code"))
    return ussd_continue(f"Welcome {_first_name(farmer)}\n{_farmer_secure_menu()}")


def _handle_farmer_secure_menu(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return ussd_continue(_farmer_secure_menu())

    if user_input == "0":
        session["state"] = STATE_ROOT
        session["data"] = {}
        return ussd_continue(_welcome_menu())

    if user_input == "9":
        session["is_authenticated"] = False
        session["user_id"] = None
        session["state"] = STATE_FARMER_MENU
        session["data"] = {}
        return ussd_end("Logged out successfully.")

    if user_input == "1":
        session["state"] = STATE_FARMER_PRODUCTS_PAGE
        session["data"] = {"products_offset": 0, "product_page_ids": []}
        return _render_farmer_products_page(session, cast(User, farmer))
    if user_input == "2":
        session["state"] = STATE_FARMER_ADD_PRODUCT_NAME
        session["data"] = {}
        return ussd_continue("Add product\nEnter product name")
    if user_input == "3":
        session["state"] = STATE_FARMER_ORDERS_PAGE
        session["data"] = {"orders_offset": 0, "order_page_ids": []}
        return _render_farmer_orders_page(session, cast(User, farmer))
    if user_input == "4":
        session["state"] = STATE_FARMER_PAYMENT_CONFIRMATIONS_PAGE
        session["data"] = {"payment_confirmations_offset": 0, "payment_confirmation_page_ids": []}
        return _render_farmer_payment_confirmations_page(session, cast(User, farmer))
    if user_input == "5":
        total_sales, orders_count = farmer_monthly_paid_sales(str(getattr(farmer, "id")))
        month_label = _utcnow().strftime("%b %Y")
        return _set_result_view(
            session,
            state=STATE_FARMER_MONTHLY_SALES_VIEW,
            message=f"Monthly Sales\n{month_label}\nPaid sales: {_money(total_sales)}\nPaid orders: {orders_count}",
            back_state=STATE_FARMER_SECURE_MENU,
            back_menu=_farmer_secure_menu(),
        )
    if user_input == "6":
        alerts = farmer_low_stock_alerts(str(getattr(farmer, "id")), limit=4)
        message = (
            "Stock Alerts\nNo low-stock alerts right now."
            if not alerts
            else "\n".join(["Stock Alerts"] + [f"{i}. {a}" for i, a in enumerate(alerts, start=1)])
        )
        return _set_result_view(
            session,
            state=STATE_FARMER_STOCK_ALERTS_VIEW,
            message=message,
            back_state=STATE_FARMER_SECURE_MENU,
            back_menu=_farmer_secure_menu(),
        )
    if user_input == "7":
        session["state"] = STATE_FARMER_BANK_PROFILE_MENU
        return _render_farmer_bank_profile_menu(session, cast(User, farmer))
    if user_input == "8":
        session["state"] = STATE_FARMER_HELP_MENU
        return _render_farmer_help_menu(session, cast(User, farmer))
    return ussd_continue(_farmer_secure_menu())


def _handle_farmer_help_menu(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return _render_farmer_help_menu(session, cast(User, farmer))
    if user_input == "0":
        session["state"] = STATE_FARMER_SECURE_MENU
        return ussd_continue(_farmer_secure_menu())
    if user_input == "1":
        return _set_paged_result_view(
            session,
            state=STATE_FARMER_HELP_VIEW,
            lines=_farmer_help_topic_text("products").split("\n"),
            back_state=STATE_FARMER_HELP_MENU,
            back_menu=_render_farmer_help_menu(session, cast(User, farmer)).message,
        )
    if user_input == "2":
        return _set_paged_result_view(
            session,
            state=STATE_FARMER_HELP_VIEW,
            lines=_farmer_help_topic_text("orders").split("\n"),
            back_state=STATE_FARMER_HELP_MENU,
            back_menu=_render_farmer_help_menu(session, cast(User, farmer)).message,
        )
    if user_input == "3":
        return _set_paged_result_view(
            session,
            state=STATE_FARMER_HELP_VIEW,
            lines=_farmer_help_topic_text("money").split("\n"),
            back_state=STATE_FARMER_HELP_MENU,
            back_menu=_render_farmer_help_menu(session, cast(User, farmer)).message,
        )
    return _render_farmer_help_menu(session, cast(User, farmer))


def _handle_farmer_product_search_input(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return ussd_continue("Search products\nEnter name, code, status, or category")
    if user_input == "0":
        session["state"] = STATE_FARMER_PRODUCTS_PAGE
        return _render_farmer_products_page(session, cast(User, farmer))

    data = cast(dict[str, Any], session.get("data") or {})
    data["product_search"] = user_input[:40]
    data["products_offset"] = 0
    session["data"] = data
    session["state"] = STATE_FARMER_PRODUCTS_PAGE
    return _render_farmer_products_page(session, cast(User, farmer), banner="Search applied.")


def _handle_farmer_order_search_input(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return ussd_continue("Search orders\nEnter buyer, ref, method, product, or code")
    if user_input == "0":
        session["state"] = STATE_FARMER_ORDERS_PAGE
        return _render_farmer_orders_page(session, cast(User, farmer))

    data = cast(dict[str, Any], session.get("data") or {})
    data["order_search"] = user_input[:40]
    data["orders_offset"] = 0
    session["data"] = data
    session["state"] = STATE_FARMER_ORDERS_PAGE
    return _render_farmer_orders_page(session, cast(User, farmer), banner="Search applied.")


def _handle_farmer_bank_profile_menu(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return _render_farmer_bank_profile_menu(session, cast(User, farmer))
    if user_input == "0":
        session["state"] = STATE_FARMER_SECURE_MENU
        session["data"] = {
            key: value
            for key, value in cast(dict[str, Any], session.get("data") or {}).items()
            if key not in {"message", "back_state", "back_menu"}
        }
        return ussd_continue(_farmer_secure_menu())
    if user_input == "1":
        profile = farmer_payment_profile_status(str(getattr(farmer, "id")))
        return _set_paged_result_view(
            session,
            state=STATE_FARMER_BANK_PROFILE_VIEW,
            lines=["Bank Profile"] + profile.split("\n"),
            back_state=STATE_FARMER_BANK_PROFILE_MENU,
            back_menu=_render_farmer_bank_profile_menu(session, cast(User, farmer)).message,
        )
    if user_input == "2":
        session["state"] = STATE_FARMER_BANK_PROFILE_BANK
        return ussd_continue(_bank_profile_bank_menu())
    if user_input == "3":
        session["state"] = STATE_FARMER_BANK_PROFILE_ACCOUNT_NAME
        return ussd_continue("Account name\nEnter account holder name")
    if user_input == "4":
        session["state"] = STATE_FARMER_BANK_PROFILE_ACCOUNT_NUMBER
        return ussd_continue("Account number\nEnter account number")
    if user_input == "5":
        session["state"] = STATE_FARMER_BANK_PROFILE_BRANCH_CODE
        return ussd_continue("Branch code\nEnter branch / EFT code")
    if user_input == "6":
        session["state"] = STATE_FARMER_BANK_PROFILE_BRANCH_TOWN
        return ussd_continue("Branch town\nEnter town or branch name")
    if user_input == "7":
        session["state"] = STATE_FARMER_BANK_PROFILE_PAYMENT_REF
        return ussd_continue("Payment ref\nEnter payment reference / instruction")
    return _render_farmer_bank_profile_menu(session, cast(User, farmer))


def _handle_farmer_bank_profile_bank(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return ussd_continue(_bank_profile_bank_menu())
    if user_input == "0":
        session["state"] = STATE_FARMER_BANK_PROFILE_MENU
        return _render_farmer_bank_profile_menu(session, cast(User, farmer))

    selected = BANK_PROFILE_BANK_CHOICES.get(_safe_str(user_input))
    if not selected:
        return ussd_continue(_bank_profile_bank_menu())

    ok, message = upsert_farmer_payment_profile(
        str(getattr(farmer, "id")),
        bank_name=_safe_str(selected.get("name")),
    )
    session["state"] = STATE_FARMER_BANK_PROFILE_MENU
    return _render_farmer_bank_profile_menu(session, cast(User, farmer), banner=message if ok else message)


def _handle_farmer_bank_profile_account_name(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return ussd_continue("Account name\nEnter account holder name")
    if user_input == "0":
        session["state"] = STATE_FARMER_BANK_PROFILE_MENU
        return _render_farmer_bank_profile_menu(session, cast(User, farmer))

    ok, message = upsert_farmer_payment_profile(
        str(getattr(farmer, "id")),
        account_name=user_input[:120],
    )
    session["state"] = STATE_FARMER_BANK_PROFILE_MENU
    return _render_farmer_bank_profile_menu(session, cast(User, farmer), banner=message)


def _handle_farmer_bank_profile_account_number(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return ussd_continue("Account number\nEnter account number")
    if user_input == "0":
        session["state"] = STATE_FARMER_BANK_PROFILE_MENU
        return _render_farmer_bank_profile_menu(session, cast(User, farmer))

    cleaned = _digits_only(_safe_str(user_input))
    if len(cleaned) < 6:
        return ussd_continue("Account number too short. Enter valid account number")

    ok, message = upsert_farmer_payment_profile(
        str(getattr(farmer, "id")),
        account_number=cleaned[:60],
    )
    session["state"] = STATE_FARMER_BANK_PROFILE_MENU
    return _render_farmer_bank_profile_menu(session, cast(User, farmer), banner=message)


def _handle_farmer_bank_profile_branch_code(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return ussd_continue("Branch code\nEnter branch / EFT code")
    if user_input == "0":
        session["state"] = STATE_FARMER_BANK_PROFILE_MENU
        return _render_farmer_bank_profile_menu(session, cast(User, farmer))

    ok, message = upsert_farmer_payment_profile(
        str(getattr(farmer, "id")),
        branch_code=_safe_str(user_input)[:40],
    )
    session["state"] = STATE_FARMER_BANK_PROFILE_MENU
    return _render_farmer_bank_profile_menu(session, cast(User, farmer), banner=message)


def _handle_farmer_bank_profile_branch_town(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return ussd_continue("Branch town\nEnter town or branch name")
    if user_input == "0":
        session["state"] = STATE_FARMER_BANK_PROFILE_MENU
        return _render_farmer_bank_profile_menu(session, cast(User, farmer))

    ok, message = upsert_farmer_payment_profile(
        str(getattr(farmer, "id")),
        branch_town=user_input[:120],
    )
    session["state"] = STATE_FARMER_BANK_PROFILE_MENU
    return _render_farmer_bank_profile_menu(session, cast(User, farmer), banner=message)


def _handle_farmer_bank_profile_payment_ref(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return ussd_continue("Payment ref\nEnter payment reference / instruction")
    if user_input == "0":
        session["state"] = STATE_FARMER_BANK_PROFILE_MENU
        return _render_farmer_bank_profile_menu(session, cast(User, farmer))

    ok, message = upsert_farmer_payment_profile(
        str(getattr(farmer, "id")),
        payment_instructions=user_input[:200],
    )
    session["state"] = STATE_FARMER_BANK_PROFILE_MENU
    return _render_farmer_bank_profile_menu(session, cast(User, farmer), banner=message)


def _handle_farmer_products_page(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return _render_farmer_products_page(session, cast(User, farmer))
    if user_input == "0":
        session["state"] = STATE_FARMER_SECURE_MENU
        session["data"] = {}
        return ussd_continue(_farmer_secure_menu())
    if _is_next_command(user_input):
        data = cast(dict[str, Any], session.get("data") or {})
        offset = int(data.get("products_offset", 0) or 0)
        next_offset = _int_or_zero(offset) + 5
        data["products_offset"] = next_offset
        session["data"] = data
        return _render_farmer_products_page(session, cast(User, farmer))
    if _is_prev_command(user_input):
        data = cast(dict[str, Any], session.get("data") or {})
        offset = int(data.get("products_offset", 0) or 0)
        data["products_offset"] = max(0, offset - 5)
        session["data"] = data
        return _render_farmer_products_page(session, cast(User, farmer))
    if _is_search_command(user_input):
        session["state"] = STATE_FARMER_PRODUCT_SEARCH_INPUT
        return ussd_continue("Search products\nEnter name, code, status, or category")
    if _is_clear_command(user_input):
        data = cast(dict[str, Any], session.get("data") or {})
        data.pop("product_search", None)
        data["products_offset"] = 0
        session["data"] = data
        return _render_farmer_products_page(session, cast(User, farmer), banner="Search cleared.")

    data = cast(dict[str, Any], session.get("data") or {})
    page_ids = cast(list[str], data.get("product_page_ids") or [])
    if user_input.isdigit():
        idx = int(user_input) - 1
        if 0 <= idx < len(page_ids):
            data["selected_product_id"] = page_ids[idx]
            session["data"] = data
            session["state"] = STATE_FARMER_PRODUCT_ACTIONS
            return _render_farmer_product_actions(session, cast(User, farmer))

    return _render_farmer_products_page(session, cast(User, farmer))


def _handle_farmer_product_actions(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    product = _selected_farmer_product(session, cast(User, farmer))
    if product is None:
        session["state"] = STATE_FARMER_PRODUCTS_PAGE
        return _render_farmer_products_page(session, cast(User, farmer), banner="Product not found.")

    if not user_input:
        return _render_farmer_product_actions(session, cast(User, farmer))
    if user_input == "0":
        session["state"] = STATE_FARMER_PRODUCTS_PAGE
        return _render_farmer_products_page(session, cast(User, farmer))
    if user_input == "1":
        summary = (
            f"Product Summary\n{_short_text(getattr(product, 'product_name', ''), 18, 'Product')}\n"
            f"Cat: {_short_text(getattr(product, 'category', ''), 14)}\n"
            f"Price: {_money(getattr(product, 'price', 0))}\n"
            f"Qty: {getattr(product, 'quantity', 0)} {getattr(product, 'unit', '')}\n"
            f"Status: {_delivery_status_label(getattr(product, 'status', 'pending'))}"
        )
        return _set_result_view(
            session,
            state=STATE_FARMER_PRODUCT_VIEW,
            message=summary,
            back_state=STATE_FARMER_PRODUCT_ACTIONS,
            back_menu=_render_farmer_product_actions(session, cast(User, farmer)).message,
        )
    if user_input == "2":
        session["state"] = STATE_FARMER_PRODUCT_UPDATE_MENU
        return ussd_continue(
            "Update Product\n1 Name\n2 Description\n3 Category\n4 Price\n5 Quantity\n6 Unit\n0 Back"
        )
    if user_input == "3":
        session["state"] = STATE_FARMER_PRODUCT_DELETE_CONFIRM
        return ussd_continue(
            f"Delete {_short_text(getattr(product, 'product_name', ''), 14)}?\n1 Confirm delete\n0 Cancel"
        )
    if user_input == "4":
        insight = farmer_product_demand_prediction(str(getattr(farmer, "id")), str(getattr(product, "product_id")))
        return _set_result_view(
            session,
            state=STATE_FARMER_PRODUCT_DEMAND_VIEW,
            message=insight,
            back_state=STATE_FARMER_PRODUCT_ACTIONS,
            back_menu=_render_farmer_product_actions(session, cast(User, farmer)).message,
        )
    if user_input == "5" and _safe_str(getattr(product, "status", "")).lower() == "rejected":
        session["state"] = STATE_FARMER_PRODUCT_REJECTION_VIEW
        return ussd_continue(
            farmer_product_rejection_summary(str(getattr(farmer, "id")), str(getattr(product, "product_id")))
        )
    return _render_farmer_product_actions(session, cast(User, farmer))


def _handle_farmer_product_rejection_view(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    product = _selected_farmer_product(session, cast(User, farmer))
    if product is None:
        session["state"] = STATE_FARMER_PRODUCTS_PAGE
        return _render_farmer_products_page(session, cast(User, farmer), banner="Product not found.")

    message = farmer_product_rejection_summary(str(getattr(farmer, "id")), str(getattr(product, "product_id")))
    if not user_input:
        return ussd_continue(message)
    if user_input == "0":
        session["state"] = STATE_FARMER_PRODUCT_ACTIONS
        return _render_farmer_product_actions(session, cast(User, farmer))
    if user_input == "1":
        session["state"] = STATE_FARMER_PRODUCT_APPEAL_INPUT
        return ussd_continue("Lodge appeal\nExplain why this product should be reviewed again")
    return ussd_continue(message)


def _handle_farmer_product_appeal_input(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    product = _selected_farmer_product(session, cast(User, farmer))
    if product is None:
        session["state"] = STATE_FARMER_PRODUCTS_PAGE
        return _render_farmer_products_page(session, cast(User, farmer), banner="Product not found.")

    if not user_input:
        return ussd_continue("Lodge appeal\nExplain why this product should be reviewed again")
    if user_input == "0":
        session["state"] = STATE_FARMER_PRODUCT_REJECTION_VIEW
        return _handle_farmer_product_rejection_view(session, "")

    ok, message = lodge_farmer_product_appeal(farmer=cast(User, farmer), product=product, appeal_text=user_input)
    return _set_result_view(
        session,
        state=STATE_FARMER_RESULT_VIEW,
        message=message,
        back_state=STATE_FARMER_PRODUCT_ACTIONS,
        back_menu=_render_farmer_product_actions(session, cast(User, farmer)).message,
    )


def _handle_farmer_product_update_menu(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return ussd_continue("Update Product\n1 Name\n2 Description\n3 Category\n4 Price\n5 Quantity\n6 Unit\n0 Back")
    if user_input == "0":
        session["state"] = STATE_FARMER_PRODUCT_ACTIONS
        return _render_farmer_product_actions(session, cast(User, farmer))
    if user_input == "1":
        session["state"] = STATE_FARMER_PRODUCT_UPDATE_NAME
        return ussd_continue("Update name\nEnter new product name")
    if user_input == "2":
        session["state"] = STATE_FARMER_PRODUCT_UPDATE_DESCRIPTION
        return ussd_continue("Update description\nEnter short description")
    if user_input == "3":
        session["state"] = STATE_FARMER_PRODUCT_UPDATE_CATEGORY
        return ussd_continue(
            "Choose category\n1 Fresh Produce\n2 Animal Products\n3 Fish & Seafood\n4 Staples\n"
            "5 Nuts/Seeds/Oils\n6 Honey/Sweeteners\n7 Value-Added\n8 Farm Supplies\n9 Wild Harvest"
        )
    if user_input == "4":
        session["state"] = STATE_FARMER_PRODUCT_UPDATE_PRICE
        return ussd_continue("Update price\nEnter new price")
    if user_input == "5":
        session["state"] = STATE_FARMER_PRODUCT_UPDATE_QTY
        return ussd_continue("Update quantity\nEnter new quantity")
    if user_input == "6":
        session["state"] = STATE_FARMER_PRODUCT_UPDATE_UNIT
        return ussd_continue("Choose unit\n1 kg\n2 each\n3 l\n4 g\n5 ml\n6 pack")
    return _handle_farmer_product_update_menu(session, "")


def _complete_farmer_product_update(session: dict[str, Any], farmer: User, field_name: str, value: Any) -> UssdResponse:
    product = _selected_farmer_product(session, farmer)
    if product is None:
        session["state"] = STATE_FARMER_PRODUCTS_PAGE
        return _render_farmer_products_page(session, farmer, banner="Product not found.")

    ok, message = update_product_for_farmer(farmer=farmer, product=product, field_name=field_name, value=value)
    return _set_result_view(
        session,
        state=STATE_FARMER_PRODUCT_VIEW,
        message=message,
        back_state=STATE_FARMER_PRODUCT_ACTIONS,
        back_menu=_render_farmer_product_actions(session, farmer).message,
    )


def _handle_farmer_product_update_name(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard
    if not user_input:
        return ussd_continue("Update name\nEnter new product name")
    if user_input == "0":
        session["state"] = STATE_FARMER_PRODUCT_UPDATE_MENU
        return _handle_farmer_product_update_menu(session, "")
    return _complete_farmer_product_update(session, cast(User, farmer), "product_name", user_input[:200])


def _handle_farmer_product_update_description(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard
    if not user_input:
        return ussd_continue("Update description\nEnter short description")
    if user_input == "0":
        session["state"] = STATE_FARMER_PRODUCT_UPDATE_MENU
        return _handle_farmer_product_update_menu(session, "")
    return _complete_farmer_product_update(session, cast(User, farmer), "description", user_input[:500])


def _handle_farmer_product_update_category(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard
    if not user_input:
        return ussd_continue(
            "Choose category\n1 Fresh Produce\n2 Animal Products\n3 Fish & Seafood\n4 Staples\n"
            "5 Nuts/Seeds/Oils\n6 Honey/Sweeteners\n7 Value-Added\n8 Farm Supplies\n9 Wild Harvest"
        )
    if user_input == "0":
        session["state"] = STATE_FARMER_PRODUCT_UPDATE_MENU
        return _handle_farmer_product_update_menu(session, "")
    category = CATEGORY_CHOICES.get(_safe_str(user_input))
    if not category:
        return ussd_continue("Invalid category. Choose 1-9")
    return _complete_farmer_product_update(session, cast(User, farmer), "category", category)


def _handle_farmer_product_update_price(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard
    if not user_input:
        return ussd_continue("Update price\nEnter new price")
    if user_input == "0":
        session["state"] = STATE_FARMER_PRODUCT_UPDATE_MENU
        return _handle_farmer_product_update_menu(session, "")
    price = _decimal_from_input(user_input)
    if price is None:
        return ussd_continue("Invalid price. Enter numeric price")
    return _complete_farmer_product_update(session, cast(User, farmer), "price", str(price))


def _handle_farmer_product_update_qty(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard
    if not user_input:
        return ussd_continue("Update quantity\nEnter new quantity")
    if user_input == "0":
        session["state"] = STATE_FARMER_PRODUCT_UPDATE_MENU
        return _handle_farmer_product_update_menu(session, "")
    quantity = _decimal_from_input(user_input)
    if quantity is None:
        return ussd_continue("Invalid quantity. Enter numeric quantity")
    return _complete_farmer_product_update(session, cast(User, farmer), "quantity", str(quantity))


def _handle_farmer_product_update_unit(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard
    if not user_input:
        return ussd_continue("Choose unit\n1 kg\n2 each\n3 l\n4 g\n5 ml\n6 pack")
    if user_input == "0":
        session["state"] = STATE_FARMER_PRODUCT_UPDATE_MENU
        return _handle_farmer_product_update_menu(session, "")
    unit = UNIT_CHOICES.get(_safe_str(user_input))
    if not unit:
        return ussd_continue("Invalid unit. Choose 1-6")
    return _complete_farmer_product_update(session, cast(User, farmer), "unit", unit)


def _handle_farmer_product_delete_confirm(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    product = _selected_farmer_product(session, cast(User, farmer))
    if product is None:
        session["state"] = STATE_FARMER_PRODUCTS_PAGE
        return _render_farmer_products_page(session, cast(User, farmer), banner="Product not found.")

    if not user_input:
        return ussd_continue(f"Delete {_short_text(getattr(product, 'product_name', ''), 14)}?\n1 Confirm delete\n0 Cancel")
    if user_input == "0":
        session["state"] = STATE_FARMER_PRODUCT_ACTIONS
        return _render_farmer_product_actions(session, cast(User, farmer))
    if user_input != "1":
        return ussd_continue("Choose 1 to confirm delete or 0 to cancel")

    ok, message = delete_product_for_farmer(farmer=cast(User, farmer), product=product)
    data = cast(dict[str, Any], session.get("data") or {})
    data.pop("selected_product_id", None)
    session["data"] = data
    session["state"] = STATE_FARMER_PRODUCTS_PAGE
    return _render_farmer_products_page(session, cast(User, farmer), banner=message)


def _handle_farmer_add_product_name(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard
    if not user_input:
        return ussd_continue("Add product\nEnter product name")
    if user_input == "0":
        session["state"] = STATE_FARMER_SECURE_MENU
        session["data"] = {}
        return ussd_continue(_farmer_secure_menu())
    session["data"] = {**(session.get("data") or {}), "product_name": user_input[:200]}
    session["state"] = STATE_FARMER_ADD_PRODUCT_DESCRIPTION
    return ussd_continue("Add description\nEnter short description\n9 Skip")


def _handle_farmer_add_product_description(session: dict[str, Any], user_input: str) -> UssdResponse:
    if not user_input:
        return ussd_continue("Add description\nEnter short description\n9 Skip")
    if user_input == "0":
        session["state"] = STATE_FARMER_SECURE_MENU
        session["data"] = {}
        return ussd_continue(_farmer_secure_menu())
    description = "" if user_input == "9" else user_input[:500]
    session["data"] = {**(session.get("data") or {}), "description": description}
    session["state"] = STATE_FARMER_ADD_PRODUCT_CATEGORY
    return ussd_continue(
        "Choose category\n"
        "1 Fresh Produce\n2 Animal Products\n3 Fish & Seafood\n4 Staples\n"
        "5 Nuts/Seeds/Oils\n6 Honey/Sweeteners\n7 Value-Added\n8 Farm Supplies\n9 Wild Harvest"
    )


def _handle_farmer_add_product_category(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard
    if not user_input:
        return ussd_continue(
            "Choose category\n1 Fresh Produce\n2 Animal Products\n3 Fish & Seafood\n4 Staples\n"
            "5 Nuts/Seeds/Oils\n6 Honey/Sweeteners\n7 Value-Added\n8 Farm Supplies\n9 Wild Harvest"
        )
    if user_input == "0":
        session["state"] = STATE_FARMER_SECURE_MENU
        session["data"] = {}
        return ussd_continue(_farmer_secure_menu())
    category = CATEGORY_CHOICES.get(_safe_str(user_input))
    if not category:
        return ussd_continue("Invalid category. Choose 1-9")
    session["data"] = {**(session.get("data") or {}), "category": category}
    session["state"] = STATE_FARMER_ADD_PRODUCT_PRICE
    return ussd_continue("Enter price")


def _handle_farmer_add_product_price(session: dict[str, Any], user_input: str) -> UssdResponse:
    if not user_input:
        return ussd_continue("Enter price")
    if user_input == "0":
        session["state"] = STATE_FARMER_SECURE_MENU
        session["data"] = {}
        return ussd_continue(_farmer_secure_menu())
    price = _decimal_from_input(user_input)
    if price is None:
        return ussd_continue("Invalid price. Enter numeric price")
    session["data"] = {**(session.get("data") or {}), "price": str(price)}
    session["state"] = STATE_FARMER_ADD_PRODUCT_QTY
    return ussd_continue("Enter quantity")


def _handle_farmer_add_product_qty(session: dict[str, Any], user_input: str) -> UssdResponse:
    if not user_input:
        return ussd_continue("Enter quantity")
    if user_input == "0":
        session["state"] = STATE_FARMER_SECURE_MENU
        session["data"] = {}
        return ussd_continue(_farmer_secure_menu())
    quantity = _decimal_from_input(user_input)
    if quantity is None:
        return ussd_continue("Invalid quantity. Enter numeric quantity")
    session["data"] = {**(session.get("data") or {}), "quantity": str(quantity)}
    session["state"] = STATE_FARMER_ADD_PRODUCT_UNIT
    return ussd_continue("Choose unit\n1 kg\n2 each\n3 l\n4 g\n5 ml\n6 pack")


def _handle_farmer_add_product_unit(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard
    if not user_input:
        return ussd_continue("Choose unit\n1 kg\n2 each\n3 l\n4 g\n5 ml\n6 pack")
    if user_input == "0":
        session["state"] = STATE_FARMER_SECURE_MENU
        session["data"] = {}
        return ussd_continue(_farmer_secure_menu())
    unit = UNIT_CHOICES.get(_safe_str(user_input))
    if not unit:
        return ussd_continue("Invalid unit. Choose 1-6")

    data = cast(dict[str, Any], session.get("data") or {})
    product_name = _safe_str(data.get("product_name"))
    description = _safe_str(data.get("description"))
    category = _safe_str(data.get("category"))
    price = _decimal_from_input(data.get("price"))
    quantity = _decimal_from_input(data.get("quantity"))
    if not product_name or not category or price is None or quantity is None:
        session["state"] = STATE_FARMER_ADD_PRODUCT_NAME
        return ussd_continue("Add product draft expired. Enter product name again")

    ok, message, product_id = create_product_for_farmer(
        farmer=cast(User, farmer),
        product_name=product_name,
        description=description,
        category=category,
        price=price,
        quantity=quantity,
        unit=unit,
    )

    session["data"] = {}
    if ok:
        _send_action_sms(
            phone_number=normalize_phone_number(session.get("phone_number")),
            user_id=str(getattr(cast(User, farmer), "id")),
            template_name="ussd_product_created",
            context={
                "product_name": product_name,
                "category": category,
                "price": str(price),
                "quantity": str(quantity),
                "unit": unit,
                "product_code": _short_public_code("P", product_id),
            },
            message=f"AgroConnect: Product {product_name} has been submitted for review. Code: {_short_public_code('P', product_id)}",
        )
        return _set_result_view(
            session,
            state=STATE_FARMER_RESULT_VIEW,
            message=f"{message}\nCode: {_short_public_code('P', product_id)}",
            back_state=STATE_FARMER_SECURE_MENU,
            back_menu=_farmer_secure_menu(),
        )

    return _set_result_view(
        session,
        state=STATE_FARMER_RESULT_VIEW,
        message=message,
        back_state=STATE_FARMER_SECURE_MENU,
        back_menu=_farmer_secure_menu(),
    )


def _handle_farmer_orders_page(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return _render_farmer_orders_page(session, cast(User, farmer))
    if user_input == "0":
        session["state"] = STATE_FARMER_SECURE_MENU
        session["data"] = {}
        return ussd_continue(_farmer_secure_menu())
    if _is_next_command(user_input):
        data = cast(dict[str, Any], session.get("data") or {})
        offset = int(data.get("orders_offset", 0) or 0)
        next_offset = _int_or_zero(offset) + 5
        data["orders_offset"] = next_offset
        session["data"] = data
        return _render_farmer_orders_page(session, cast(User, farmer))
    if _is_prev_command(user_input):
        data = cast(dict[str, Any], session.get("data") or {})
        offset = int(data.get("orders_offset", 0) or 0)
        data["orders_offset"] = max(0, offset - 5)
        session["data"] = data
        return _render_farmer_orders_page(session, cast(User, farmer))
    if _is_search_command(user_input):
        session["state"] = STATE_FARMER_ORDER_SEARCH_INPUT
        return ussd_continue("Search orders\nEnter buyer, ref, method, product, or code")
    if _is_clear_command(user_input):
        data = cast(dict[str, Any], session.get("data") or {})
        data.pop("order_search", None)
        data["orders_offset"] = 0
        session["data"] = data
        return _render_farmer_orders_page(session, cast(User, farmer), banner="Search cleared.")

    data = cast(dict[str, Any], session.get("data") or {})
    page_ids = cast(list[str], data.get("order_page_ids") or [])
    if user_input.isdigit():
        idx = int(user_input) - 1
        if 0 <= idx < len(page_ids):
            data["selected_order_id"] = page_ids[idx]
            session["data"] = data
            session["state"] = STATE_FARMER_ORDER_ACTIONS
            return _render_farmer_order_actions(session, cast(User, farmer))

    return _render_farmer_orders_page(session, cast(User, farmer))


def _handle_farmer_order_actions(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return _render_farmer_order_actions(session, cast(User, farmer))
    if user_input == "0":
        session["state"] = STATE_FARMER_ORDERS_PAGE
        return _render_farmer_orders_page(session, cast(User, farmer))

    data = cast(dict[str, Any], session.get("data") or {})
    order_id = _safe_str(data.get("selected_order_id"))
    detail = farmer_order_detail(str(getattr(farmer, "id")), order_id) if order_id else None
    if not detail:
        session["state"] = STATE_FARMER_ORDERS_PAGE
        return _render_farmer_orders_page(session, cast(User, farmer), banner="Order not found.")

    if user_input == "1":
        financials = _quote_financials(detail.get("farmer_total"), detail.get("delivery_fee"))
        message_lines = [
            "Payment",
            f"Status: {_safe_str(detail.get('payment_status'), 'unpaid')}",
            f"Method: {_short_text(_payment_method_label(detail.get('payment_method')), 14)}",
            f"Products: {_money(financials['products_subtotal'])}",
            f"Delivery: {_money(financials['delivery_fee'])}",
            f"VAT: {_money(financials['vat_amount'])}",
            f"Total: {_money(financials['grand_total'])}",
            f"Ref: {_short_text(detail.get('payment_reference'), 14)}",
        ]
        return _set_result_view(
            session,
            state=STATE_FARMER_ORDER_PAYMENT_VIEW,
            message="\n".join(message_lines),
            back_state=STATE_FARMER_ORDER_ACTIONS,
            back_menu=_render_farmer_order_actions(session, cast(User, farmer)).message,
        )
    if user_input == "2":
        session["state"] = STATE_FARMER_ORDER_DELIVERY_MENU
        current_label = _delivery_status_label(detail.get("delivery_status"))
        return ussd_continue(
            f"Delivery Status\nCurrent: {current_label}\n1 Pending\n2 In transit\n3 Delivered\n4 Ready/Pickup\n0 Back"
        )
    if user_input == "3":
        if _safe_str(detail.get("delivery_method")).lower() != "delivery":
            return ussd_continue("Pickup order has no delivery fee\nUse Ready for payment\n0 Back")
        session["state"] = STATE_FARMER_ORDER_DELIVERY_FEE_INPUT
        return ussd_continue("Set delivery fee\nEnter amount in N$\n0 Back")
    if user_input == "4":
        if _safe_str(detail.get("delivery_method")).lower() == "delivery" and _decimal_or_zero(detail.get("delivery_fee")) <= Decimal("0.00"):
            return ussd_continue("Set delivery fee first\nUse option 3\n0 Back")
        session["state"] = STATE_FARMER_ORDER_READY_FOR_PAYMENT_CONFIRM
        data.pop("pending_delivery_fee", None)
        session["data"] = data
        return _render_farmer_ready_for_payment_confirm(session, cast(User, farmer))
    return _render_farmer_order_actions(session, cast(User, farmer))


def _handle_farmer_order_delivery_fee_input(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return ussd_continue("Set delivery fee\nEnter amount in N$\n0 Back")
    if user_input == "0":
        session["state"] = STATE_FARMER_ORDER_ACTIONS
        return _render_farmer_order_actions(session, cast(User, farmer))

    fee_value = _decimal_from_input(user_input)
    if fee_value is None:
        return ussd_continue("Invalid amount\nEnter amount in N$\n0 Back")

    data = cast(dict[str, Any], session.get("data") or {})
    data["pending_delivery_fee"] = str(fee_value.quantize(Decimal("0.01")))
    session["data"] = data
    session["state"] = STATE_FARMER_ORDER_READY_FOR_PAYMENT_CONFIRM
    return _render_farmer_ready_for_payment_confirm(session, cast(User, farmer))


def _handle_farmer_order_ready_for_payment_confirm(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return _render_farmer_ready_for_payment_confirm(session, cast(User, farmer))
    if user_input == "0":
        session["state"] = STATE_FARMER_ORDER_ACTIONS
        return _render_farmer_order_actions(session, cast(User, farmer))
    if user_input != "1":
        return _render_farmer_ready_for_payment_confirm(session, cast(User, farmer))

    data = cast(dict[str, Any], session.get("data") or {})
    order_id = _safe_str(data.get("selected_order_id"))
    detail = farmer_order_detail(str(getattr(farmer, "id")), order_id) if order_id else None
    if not detail:
        session["state"] = STATE_FARMER_ORDERS_PAGE
        return _render_farmer_orders_page(session, cast(User, farmer), banner="Order not found.")

    pending_fee = _safe_str(data.get("pending_delivery_fee"))
    delivery_fee_value = _decimal_or_zero(pending_fee) if pending_fee else _decimal_or_zero(detail.get("delivery_fee"))
    ok, message = farmer_apply_delivery_quote(
        farmer=cast(User, farmer),
        order_id=order_id,
        delivery_fee=delivery_fee_value,
    )
    data.pop("pending_delivery_fee", None)
    session["data"] = data

    if ok:
        return _set_result_view(
            session,
            state=STATE_FARMER_RESULT_VIEW,
            message=message,
            back_state=STATE_FARMER_ORDER_ACTIONS,
            back_menu=_render_farmer_order_actions(session, cast(User, farmer)).message,
        )
    return ussd_continue(f"{message}\n0 Back")


def _handle_farmer_order_delivery_menu(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    data = cast(dict[str, Any], session.get("data") or {})
    order_id = _safe_str(data.get("selected_order_id"))
    detail = farmer_order_detail(str(getattr(farmer, "id")), order_id) if order_id else None
    if not detail:
        session["state"] = STATE_FARMER_ORDERS_PAGE
        return _render_farmer_orders_page(session, cast(User, farmer), banner="Order not found.")

    if not user_input:
        current_label = _delivery_status_label(detail.get("delivery_status"))
        return ussd_continue(
            f"Delivery Status\nCurrent: {current_label}\n1 Pending\n2 In transit\n3 Delivered\n4 Ready/Pickup\n0 Back"
        )
    if user_input == "0":
        session["state"] = STATE_FARMER_ORDER_ACTIONS
        return _render_farmer_order_actions(session, cast(User, farmer))

    mapped = {"1": "pending", "2": "in_transit", "3": "delivered", "4": "ready"}.get(user_input)
    if not mapped:
        return ussd_continue("Choose 1, 2, 3, 4 or 0 Back")

    ok, message = update_farmer_order_delivery_status(str(getattr(farmer, "id")), order_id, mapped)
    return _set_result_view(
        session,
        state=STATE_FARMER_RESULT_VIEW,
        message=message,
        back_state=STATE_FARMER_ORDER_ACTIONS,
        back_menu=_render_farmer_order_actions(session, cast(User, farmer)).message,
    )


# Customer handlers
def _handle_farmer_payment_confirmations_page(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return _render_farmer_payment_confirmations_page(session, cast(User, farmer))
    if user_input == "0":
        session["state"] = STATE_FARMER_SECURE_MENU
        session["data"] = {}
        return ussd_continue(_farmer_secure_menu())
    if _is_next_command(user_input):
        data = cast(dict[str, Any], session.get("data") or {})
        offset = int(data.get("payment_confirmations_offset", 0) or 0)
        data["payment_confirmations_offset"] = _int_or_zero(offset) + 5
        session["data"] = data
        return _render_farmer_payment_confirmations_page(session, cast(User, farmer))
    if _is_prev_command(user_input):
        data = cast(dict[str, Any], session.get("data") or {})
        offset = int(data.get("payment_confirmations_offset", 0) or 0)
        data["payment_confirmations_offset"] = max(0, offset - 5)
        session["data"] = data
        return _render_farmer_payment_confirmations_page(session, cast(User, farmer))

    data = cast(dict[str, Any], session.get("data") or {})
    page_ids = cast(list[str], data.get("payment_confirmation_page_ids") or [])
    if user_input.isdigit():
        idx = int(user_input) - 1
        if 0 <= idx < len(page_ids):
            data["selected_payment_confirmation_order_id"] = page_ids[idx]
            session["data"] = data
            session["state"] = STATE_FARMER_PAYMENT_CONFIRMATION_ACTIONS
            return _render_farmer_payment_confirmation_actions(session, cast(User, farmer))

    return _render_farmer_payment_confirmations_page(session, cast(User, farmer))


def _handle_farmer_payment_confirmation_actions(session: dict[str, Any], user_input: str) -> UssdResponse:
    farmer, guard = _require_authenticated_farmer(session)
    if guard is not None:
        return guard

    if not user_input:
        return _render_farmer_payment_confirmation_actions(session, cast(User, farmer))
    if user_input == "0":
        session["state"] = STATE_FARMER_PAYMENT_CONFIRMATIONS_PAGE
        return _render_farmer_payment_confirmations_page(session, cast(User, farmer))
    if user_input not in {"1", "2"}:
        return _render_farmer_payment_confirmation_actions(session, cast(User, farmer))

    data = cast(dict[str, Any], session.get("data") or {})
    order_id = _safe_str(data.get("selected_payment_confirmation_order_id"))
    ok, message = farmer_review_payment_reference(
        farmer_id=str(getattr(farmer, "id")),
        order_id=order_id,
        approved=(user_input == "1"),
    )
    session["state"] = STATE_FARMER_PAYMENT_CONFIRMATIONS_PAGE
    data.pop("selected_payment_confirmation_order_id", None)
    session["data"] = data
    return _render_farmer_payment_confirmations_page(session, cast(User, farmer), banner=message)


# Customer handlers
# ---------------------------------------------------------------------------
def _handle_customer_menu(session: dict[str, Any], user_input: str) -> UssdResponse:
    phone_number = normalize_phone_number(session.get("phone_number"))
    menu_text = _public_customer_menu(phone_number)
    already_active = _has_ussd_pin_for_phone(phone_number) and _find_user_by_phone(phone_number, role=ROLE_CUSTOMER) is not None

    if not user_input:
        return ussd_continue(menu_text)

    if user_input == "0":
        session["state"] = STATE_ROOT
        return ussd_continue(_welcome_menu())

    if already_active:
        if user_input == "1":
            session["state"] = STATE_CUSTOMER_LOGIN_PIN
            session["data"] = {}
            return ussd_continue("Login\nEnter your 4-digit PIN")
        if user_input == "2":
            existing = _find_user_by_phone(phone_number, role=ROLE_CUSTOMER)
            if existing is None:
                return ussd_continue(menu_text)
            session["state"] = STATE_CUSTOMER_REGISTER_PIN
            session["data"] = {
                "existing_activation": True,
                "full_name": _safe_str(getattr(existing, "full_name", "")),
                "location": _safe_str(getattr(existing, "location", "")),
            }
            return ussd_continue("Reset PIN\nSet new 4-digit USSD PIN")
        if user_input == "3":
            return ussd_continue("Customer Help\nLogin to browse categories, orders and payment info.\n0 Back")
        return ussd_continue(menu_text)

    if user_input == "1":
        existing = _find_user_by_phone(phone_number)
        if existing is not None:
            existing_role = int(getattr(existing, "role", 0) or 0)
            if existing_role != int(ROLE_CUSTOMER):
                return ussd_end("This phone number already belongs to a different account type.")
            session["state"] = STATE_CUSTOMER_REGISTER_PIN
            session["data"] = {
                "existing_activation": True,
                "full_name": _safe_str(getattr(existing, "full_name", "")),
                "location": _safe_str(getattr(existing, "location", "")),
            }
            return ussd_continue("Customer account found.\nSet 4-digit USSD PIN")
        session["state"] = STATE_CUSTOMER_REGISTER_NAME
        session["data"] = {"existing_activation": False}
        return ussd_continue("Register / Activate USSD\nEnter full name")

    if user_input == "2":
        session["state"] = STATE_CUSTOMER_LOGIN_PIN
        session["data"] = {}
        return ussd_continue("Login\nEnter your 4-digit PIN")

    if user_input == "3":
        return ussd_continue("Customer Help\nActivate once, then login with your PIN.\n0 Back")

    return ussd_continue(menu_text)


def _handle_customer_register_name(session: dict[str, Any], user_input: str) -> UssdResponse:
    if not user_input:
        return ussd_continue("Register / Activate USSD\nEnter full name")
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_MENU
        session["data"] = {}
        return ussd_continue(_public_customer_menu(normalize_phone_number(session.get("phone_number"))))

    data = {**(session.get("data") or {}), "full_name": user_input[:200]}
    session["data"] = data
    if bool(data.get("existing_activation")):
        session["state"] = STATE_CUSTOMER_REGISTER_PIN
        return ussd_continue("Set 4-digit USSD PIN")

    session["state"] = STATE_CUSTOMER_REGISTER_EMAIL
    return ussd_continue("Enter email for web login")


def _handle_customer_register_email(session: dict[str, Any], user_input: str) -> UssdResponse:
    if not user_input:
        return ussd_continue("Enter email for web login")
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_REGISTER_NAME
        return ussd_continue("Register / Activate USSD\nEnter full name")

    email_value = _normalize_email(user_input)
    if not _email_is_valid(email_value):
        return ussd_continue("Valid email required\nEnter email for web login")

    existing_email = db.session.execute(select(User).where(User.email == email_value)).scalar_one_or_none()
    if existing_email is not None:
        return ussd_continue("Email already registered\nEnter another email")

    session["data"] = {**(session.get("data") or {}), "email": email_value}
    session["state"] = STATE_CUSTOMER_REGISTER_WEB_PASSWORD
    return ussd_continue(_registration_password_prompt())


def _handle_customer_register_web_password(session: dict[str, Any], user_input: str) -> UssdResponse:
    if not user_input:
        return ussd_continue(_registration_password_prompt())
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_REGISTER_EMAIL
        return ussd_continue("Enter email for web login")

    password_error = _web_password_validation_error(user_input)
    if password_error:
        return ussd_continue(f"{password_error}\n6-12 chars, no * or #")

    session["data"] = {**(session.get("data") or {}), "web_password": user_input}
    session["state"] = STATE_CUSTOMER_REGISTER_WEB_PASSWORD_CONFIRM
    return ussd_continue("Retype web password")


def _handle_customer_register_web_password_confirm(session: dict[str, Any], user_input: str) -> UssdResponse:
    data = cast(dict[str, Any], session.get("data") or {})
    if not user_input:
        return ussd_continue("Retype web password")
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_REGISTER_WEB_PASSWORD
        return ussd_continue(_registration_password_prompt())

    first_password = _safe_str(data.get("web_password"))
    if user_input != first_password:
        data.pop("web_password", None)
        session["data"] = data
        session["state"] = STATE_CUSTOMER_REGISTER_WEB_PASSWORD
        return ussd_continue("Passwords do not match\nSet web password again")

    session["state"] = STATE_CUSTOMER_REGISTER_PIN
    return ussd_continue("Set 4-digit USSD PIN")


def _handle_customer_register_pin(session: dict[str, Any], user_input: str) -> UssdResponse:
    data = cast(dict[str, Any], session.get("data") or {})
    existing = bool(data.get("existing_activation"))
    prompt = "Set new 4-digit USSD PIN" if existing else "Set 4-digit USSD PIN"
    if not user_input:
        return ussd_continue(prompt)
    if user_input == "0":
        if existing:
            session["state"] = STATE_CUSTOMER_MENU
            session["data"] = {}
            return ussd_continue(_public_customer_menu(normalize_phone_number(session.get("phone_number"))))
        session["state"] = STATE_CUSTOMER_REGISTER_WEB_PASSWORD_CONFIRM
        return ussd_continue("Retype web password")

    pin = _safe_str(user_input)
    if not _pin_is_valid(pin):
        return ussd_continue("PIN must be exactly 4 digits. Enter 4-digit PIN")

    full_name = _safe_str(data.get("full_name"))
    email = _normalize_email(data.get("email"))
    web_password = _safe_str(data.get("web_password"))
    phone_number = normalize_phone_number(session.get("phone_number"))

    ok, customer, message = activate_or_register_ussd_user(
        phone_number=phone_number,
        role_value=ROLE_CUSTOMER,
        full_name=full_name,
        email=email,
        web_password=web_password,
        pin=pin,
    )
    if not ok or customer is None:
        if not existing and message in {"Email address is already registered.", "Valid email is required.", "Email is required."}:
            session["state"] = STATE_CUSTOMER_REGISTER_EMAIL
            return ussd_continue(f"{message}\nEnter email for web login")
        if not existing and message in {"Web password is required."}:
            session["state"] = STATE_CUSTOMER_REGISTER_WEB_PASSWORD
            return ussd_continue("Web password required\nSet web password")
        session["state"] = STATE_CUSTOMER_MENU
        session["data"] = {}
        return ussd_continue(f"{message}\n0 Back")

    session["is_authenticated"] = True
    session["user_id"] = str(getattr(customer, "id"))
    session["state"] = STATE_CUSTOMER_SECURE_MENU
    session["data"] = {}

    _touch_user_auth_timestamps(user_id=getattr(customer, "id"), update_login=True)
    _clear_registration_drafts_for_phone(phone_number, session.get("service_code"))

    _send_action_sms(
        phone_number=phone_number,
        user_id=str(getattr(customer, "id")),
        template_name="ussd_customer_activation",
        context={"full_name": getattr(customer, "full_name", ""), "email": getattr(customer, "email", "")},
        message="AgroConnect: Your customer web account and USSD access are ready. You are now logged in.",
    )

    banner = "USSD activated successfully." if existing else message
    return ussd_continue(f"{banner}\nWelcome {_first_name(customer)}\n{_customer_secure_menu()}")



def _handle_customer_login_pin(session: dict[str, Any], user_input: str) -> UssdResponse:
    if not user_input:
        return ussd_continue("Login\nEnter your 4-digit PIN")
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_MENU
        return ussd_continue(_public_customer_menu(normalize_phone_number(session.get("phone_number"))))

    pin = _safe_str(user_input)
    if not _pin_is_valid(pin):
        return ussd_continue("PIN must be exactly 4 digits. Enter your 4-digit PIN")

    phone_number = normalize_phone_number(session.get("phone_number"))
    ok, user_id, message = _verify_ussd_pin(phone_number, pin)
    if not ok or not user_id:
        return ussd_continue(message)

    customer = db.session.get(User, uuid.UUID(user_id))
    if customer is None or int(getattr(customer, "role", 0) or 0) != int(ROLE_CUSTOMER):
        return ussd_end("Customer account not found for this phone number.")

    session["is_authenticated"] = True
    session["user_id"] = user_id
    session["state"] = STATE_CUSTOMER_SECURE_MENU
    session["data"] = {}
    _clear_registration_drafts_for_phone(phone_number, session.get("service_code"))
    return ussd_continue(f"Welcome {_first_name(customer)}\n{_customer_secure_menu()}")


def _render_customer_products_page(session: dict[str, Any], customer: User, banner: str = "") -> UssdResponse:
    page_size = 4
    data = cast(dict[str, Any], session.get("data") or {})
    offset = int(data.get("products_offset", 0) or 0)
    search_term = _safe_str(data.get("customer_product_search"))
    category_filter = _safe_str(data.get("customer_category_filter"))

    rows = customer_searchable_products(search_term=search_term, category=category_filter, limit=page_size, offset=offset)

    if not rows and offset > 0:
        data["products_offset"] = max(0, offset - page_size)
        session["data"] = data
        return _render_customer_products_page(session, customer, banner=banner)

    lines: list[str] = []
    if banner:
        lines.append(banner)
    lines.append("Products")

    if category_filter:
        lines.append(f"Cat: {_short_text(category_filter, 18)}")
    if search_term:
        lines.append(f"Find: {_short_text(search_term, 18)}")

    if not rows:
        lines.append("No products found.")
    else:
        page_ids: list[str] = []
        for idx, row in enumerate(rows, start=1):
            page_ids.append(_safe_str(row.get("product_id")))
            lines.append(
                f"{idx}. {_short_text(row.get('product_name'), 13)} {_money(row.get('price'))}/{_short_text(row.get('unit'), 4)}"
            )
        data["customer_product_page_ids"] = page_ids
        session["data"] = data

    if len(rows) == page_size:
        lines.append("N Next")
    if offset > 0:
        lines.append("P Prev")
    lines.append("S Search")
    if search_term or category_filter:
        lines.append("C Clear")
    lines.append("0 Back")
    return ussd_continue("\n".join(lines))


def _selected_customer_product(session: dict[str, Any]) -> Optional[dict[str, Any]]:
    data = cast(dict[str, Any], session.get("data") or {})
    product_id = _safe_str(data.get("selected_customer_product_id"))
    if not product_id:
        return None
    return customer_product_detail(product_id)


def _customer_unit_label(unit_value: Any) -> str:
    """
    Human-friendly unit label for compact USSD screens.

    WHY THIS HELPER EXISTS:
      • product records can store short DB units like ``each`` or ``kg``
      • customer screens should use clear buyer wording such as ``item``
      • dynamic labels make product actions easier to understand
    """
    normalized = _safe_str(unit_value, "each").lower()
    mapping = {
        "each": "item",
        "ea": "item",
        "item": "item",
        "kg": "kg",
        "g": "g",
        "l": "l",
        "ml": "ml",
        "pack": "pack",
        "pkt": "pack",
    }
    return mapping.get(normalized, normalized or "item")


def _customer_qty_text(quantity: Any, unit_value: Any = "") -> str:
    """Return a buyer-friendly quantity like ``4 item`` or ``1.5 kg``."""
    qty_decimal = _decimal_or_zero(quantity)
    try:
        qty_text = format(qty_decimal.normalize(), "f").rstrip("0").rstrip(".")
    except Exception:
        qty_text = _safe_str(quantity, "0")
    unit_label = _customer_unit_label(unit_value)
    return f"{qty_text} {unit_label}".strip()


def _customer_add_one_label(unit_value: Any) -> str:
    unit_label = _customer_unit_label(unit_value)
    return f"Add 1 {unit_label}"


def _customer_enter_amount_label(unit_value: Any) -> str:
    unit_label = _customer_unit_label(unit_value)
    if unit_label in {"kg", "g", "l", "ml"}:
        return f"Enter {unit_label} amount"
    if unit_label == "pack":
        return "Enter pack quantity"
    return "Enter item quantity"


def _render_customer_product_actions(session: dict[str, Any], customer: User, banner: str = "") -> UssdResponse:
    """
    Render buyer-facing product details with seller context and unit-aware
    labels so the customer immediately knows:
      • who is selling the product
      • where it comes from
      • how it is sold
      • what action will be added to the cart
    """
    detail = _selected_customer_product(session)
    if not detail:
        session["state"] = STATE_CUSTOMER_PRODUCTS_PAGE
        return _render_customer_products_page(session, customer, banner="Product no longer available.")

    product_unit = _safe_str(detail.get("unit"), "each")
    cart_qty = customer_cart_qty_for_product(str(getattr(customer, "id")), _safe_str(detail.get("product_id")))

    lines: list[str] = []
    if banner:
        lines.append(banner)
    lines.extend(
        [
            "Product Details",
            _short_text(detail.get("product_name"), 20, "Product"),
            f"Sold by: {_customer_unit_label(product_unit)}",
            f"Price: {_money(detail.get('price'))} per {_customer_unit_label(product_unit)}",
            f"Available: {_customer_qty_text(detail.get('quantity'), product_unit)}",
            f"Farmer: {_short_text(detail.get('farmer_name'), 18, 'Farmer')}",
            f"Location: {_short_text(detail.get('farmer_location'), 18, 'Not set')}",
            f"In cart: {_customer_qty_text(cart_qty, product_unit)}",
            f"1 {_customer_add_one_label(product_unit)}",
            f"2 {_customer_enter_amount_label(product_unit)}",
            "0 Back",
        ]
    )
    return ussd_continue("\n".join(lines))


def _render_customer_cart_page(session: dict[str, Any], customer: User, banner: str = "") -> UssdResponse:
    """
    Render the buyer cart using the same friendly unit language used on the
    product-detail screen.

    WHY THIS HELPS:
      • keeps cart rows readable on small USSD screens
      • shows quantities as ``4 item`` or ``1.5 kg`` instead of cramped DB-style labels
      • makes the cart feel like part of the same customer journey as search/details
    """
    page_size = 4
    data = cast(dict[str, Any], session.get("data") or {})
    offset = int(data.get("cart_offset", 0) or 0)
    snapshot = customer_cart_snapshot(str(getattr(customer, "id")))
    rows = cast(list[dict[str, Any]], snapshot.get("items") or [])

    if offset > 0 and offset >= len(rows):
        offset = max(0, offset - page_size)
        data["cart_offset"] = offset
        session["data"] = data

    page_rows = rows[offset : _int_or_zero(offset) + page_size]

    lines: list[str] = []
    if banner:
        lines.append(banner)
    lines.append("My Cart")

    if not page_rows:
        lines.append("Cart is empty.")
    else:
        page_ids: list[str] = []
        for idx, row in enumerate(page_rows, start=1):
            page_ids.append(_safe_str(row.get("cart_item_id")))
            unit_value = _safe_str(row.get("unit"), "each")
            qty_label = _customer_qty_text(row.get("qty"), unit_value)
            lines.append(
                f"{idx}. {_short_text(row.get('product_name'), 10)} {qty_label} {_money(row.get('line_total'))}"
            )
        data["customer_cart_page_ids"] = page_ids
        session["data"] = data

    lines.append(f"Subtotal: {_money(snapshot.get('subtotal'))}")
    if _int_or_zero(offset) + page_size < len(rows):
        lines.append("N Next")
    if offset > 0:
        lines.append("P Prev")
    if rows:
        lines.append("8 Checkout")
        lines.append("9 Clear cart")
    lines.append("0 Back")
    return ussd_continue("\n".join(lines))


def _selected_customer_cart_item(session: dict[str, Any], customer: User) -> Optional[dict[str, Any]]:
    selected_id = _safe_str(cast(dict[str, Any], session.get("data") or {}).get("selected_customer_cart_item_id"))
    if not selected_id:
        return None
    snapshot = customer_cart_snapshot(str(getattr(customer, "id")))
    for row in cast(list[dict[str, Any]], snapshot.get("items") or []):
        if _safe_str(row.get("cart_item_id")) == selected_id:
            return row
    return None


def _render_customer_cart_item_actions(session: dict[str, Any], customer: User, banner: str = "") -> UssdResponse:
    """
    Render one selected cart item using the same buyer-friendly unit language
    used on the product-detail screen.

    WHY THIS HELPS:
      • keeps quantity labels consistent between product search and cart review
      • removes vague actions like "Add 1" when the item is sold per kg / pack / item
      • improves confidence for remote USSD buyers before checkout
    """
    row = _selected_customer_cart_item(session, customer)
    if not row:
        session["state"] = STATE_CUSTOMER_CART_PAGE
        return _render_customer_cart_page(session, customer, banner="Cart item not found.")

    unit_value = _safe_str(row.get("unit"), "each")
    lines: list[str] = []
    if banner:
        lines.append(banner)
    lines.extend(
        [
            "Cart Item",
            _short_text(row.get("product_name"), 20),
            f"Qty: {_customer_qty_text(row.get('qty'), unit_value)}",
            f"Price: {_money(row.get('unit_price'))} per {_customer_unit_label(unit_value)}",
            f"Line: {_money(row.get('line_total'))}",
            f"1 {_customer_add_one_label(unit_value)}",
            f"2 {_customer_enter_amount_label(unit_value)}",
            "3 Remove",
            "0 Back",
        ]
    )
    return ussd_continue("\n".join(lines))


def _render_customer_orders_page(session: dict[str, Any], customer: User) -> UssdResponse:
    page_size = 3
    data = cast(dict[str, Any], session.get("data") or {})
    offset = int(data.get("orders_offset", 0) or 0)
    rows = customer_latest_orders(str(getattr(customer, "id")), limit=page_size, offset=offset)

    if not rows and offset == 0:
        return ussd_continue("My Orders\nNo orders yet.\n0 Back")

    if not rows and offset > 0:
        offset = max(0, offset - page_size)
        data["orders_offset"] = offset
        session["data"] = data
        rows = customer_latest_orders(str(getattr(customer, "id")), limit=page_size, offset=offset)

    order_page_ids: list[str] = []
    lines = ["My Orders"]
    for idx, row in enumerate(rows, start=1):
        order_page_ids.append(_safe_str(row.get("order_id")))
        order_date = row.get("order_date")
        date_label = order_date.strftime("%d/%m") if isinstance(order_date, datetime) else "--/--"
        order_code = _short_public_code("O", row.get("order_id"))
        status = _safe_str(row.get("status"), "-")
        total = _money(row.get("order_total"))
        lines.append(f"{idx}. {order_code} {date_label} {status[:7]} {total}")

    data["customer_order_page_ids"] = order_page_ids
    data["orders_offset"] = offset
    session["data"] = data

    if len(rows) == page_size:
        lines.append("N Next")
    if offset > 0:
        lines.append("P Prev")
    lines.append("0 Back")
    return ussd_continue("\n".join(lines))


def _render_customer_order_detail(session: dict[str, Any], customer: User, banner: str = "") -> UssdResponse:
    data = cast(dict[str, Any], session.get("data") or {})
    order_id = _safe_str(data.get("selected_customer_order_id"))
    detail = customer_order_detail(str(getattr(customer, "id")), order_id) if order_id else None

    if not detail:
        session["state"] = STATE_CUSTOMER_ORDERS_PAGE
        data.pop("selected_customer_order_id", None)
        session["data"] = data
        return _render_customer_orders_page(session, customer)

    order_code = _short_public_code("O", detail.get("order_id"))
    payment_status = _safe_str(detail.get("payment_status"), "unpaid")
    payment_method = _safe_str(detail.get("payment_method"), "-")
    payment_reference = _safe_str(detail.get("payment_reference"))
    has_reference_submission = bool(payment_reference) and payment_reference != order_code
    supports_reference = _payment_supports_reference_confirmation(payment_method)
    status_label = _payment_customer_status_label(
        payment_status,
        payment_method=payment_method,
        has_reference_submission=has_reference_submission and supports_reference,
    )

    lines: list[str] = []
    if banner:
        lines.append(banner)
    quote_ready = _delivery_quote_is_ready(detail.get("delivery_fee_status"))
    financials = _quote_financials(detail.get("order_total"), detail.get("delivery_fee"))
    stage_label = _customer_checkout_stage_label(detail.get("delivery_method"), detail.get("delivery_fee_status"))
    lines.extend(
        [
            "Order Details",
            f"{order_code} {_date_label(detail.get('order_date'))}",
            f"Stage: {_short_text(stage_label, 24)}",
            f"Status: {_short_text(_safe_str(detail.get('status'), 'pending').title(), 18)}",
            f"Pay status: {_short_text(status_label, 22)}",
            f"Method: {_short_text(_payment_method_label(payment_method), 16)}",
            f"Delivery: {_short_text(_safe_str(detail.get('delivery_method'), '-').title(), 16)}",
            f"Del status: {_short_text(_delivery_status_label(detail.get('delivery_status')), 16)}",
            f"Farmer: {_short_text(detail.get('farmer_name'), 18, 'Farmer')}",
            f"Location: {_short_text(detail.get('farmer_location'), 18, 'Not set')}",
        ]
    )
    if _safe_str(detail.get('delivery_method')).lower() == 'delivery':
        lines.append(f"Addr: {_short_text(detail.get('delivery_address'), 18, 'not set')}")
    lines.append(f"Products: {_money(financials['products_subtotal'])}")
    if quote_ready:
        lines.append(f"Delivery fee: {_money(financials['delivery_fee'])}")
        lines.append(f"VAT: {_money(financials['vat_amount'])}")
        lines.append(f"Grand total: {_money(financials['grand_total'])}")
    else:
        lines.append("Delivery fee: waiting")
        lines.append("VAT: after quote")

    if has_reference_submission:
        lines.append(f"Payment ref: {_short_text(payment_reference, 18)}")
    elif supports_reference and quote_ready:
        lines.append(f"Order ref: {order_code}")

    if quote_ready and supports_reference and payment_status.lower() in {'unpaid', 'pending', 'failed'}:
        lines.append("1 Continue payment")
    else:
        lines.append("1 Payment info")
    lines.append("0 Back")
    return ussd_continue("\n".join(lines))

def _handle_customer_checkout_review(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    if not user_input:
        return _render_customer_checkout_review(session, cast(User, customer))
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_CHECKOUT_PAYMENT_METHOD
        return ussd_continue("Payment method\n1 Cash\n2 Mobile Wallet\n3 EFT / Bank\n0 Back")
    if user_input != "1":
        return _render_customer_checkout_review(session, cast(User, customer))

    data = cast(dict[str, Any], session.get("data") or {})
    delivery_method = _safe_str(data.get("checkout_delivery_method"), "delivery")
    payment_method = _safe_str(data.get("checkout_payment_method"), "cash")
    delivery_address = _safe_str(data.get("checkout_delivery_address"))

    ok, message = customer_checkout_from_cart(
        customer=cast(User, customer),
        delivery_method=delivery_method,
        payment_method=payment_method,
        delivery_address=delivery_address,
    )

    data.pop("checkout_delivery_method", None)
    data.pop("checkout_delivery_address", None)
    data.pop("checkout_payment_method", None)
    session["data"] = data

    session["state"] = STATE_CUSTOMER_RESULT_VIEW
    return _set_result_view(
        session,
        state=STATE_CUSTOMER_RESULT_VIEW,
        message=message,
        back_state=STATE_CUSTOMER_SECURE_MENU,
        back_menu=_customer_secure_menu(),
    )


def _handle_customer_orders_page(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard
    if not user_input:
        return _render_customer_orders_page(session, cast(User, customer))
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_SECURE_MENU
        session["data"] = {}
        return ussd_continue(_customer_secure_menu())
    if _is_next_command(user_input):
        data = cast(dict[str, Any], session.get("data") or {})
        offset = int(data.get("orders_offset", 0) or 0)
        data["orders_offset"] = _int_or_zero(offset) + 3
        session["data"] = data
        return _render_customer_orders_page(session, cast(User, customer))
    if _is_prev_command(user_input):
        data = cast(dict[str, Any], session.get("data") or {})
        offset = int(data.get("orders_offset", 0) or 0)
        data["orders_offset"] = max(0, offset - 3)
        session["data"] = data
        return _render_customer_orders_page(session, cast(User, customer))

    data = cast(dict[str, Any], session.get("data") or {})
    page_ids = cast(list[str], data.get("customer_order_page_ids") or [])
    if user_input.isdigit():
        idx = int(user_input) - 1
        if 0 <= idx < len(page_ids):
            data["selected_customer_order_id"] = page_ids[idx]
            session["data"] = data
            session["state"] = STATE_CUSTOMER_ORDER_DETAIL
            return _render_customer_order_detail(session, cast(User, customer))

    return _render_customer_orders_page(session, cast(User, customer))


def _handle_customer_order_detail(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    if not user_input:
        return _render_customer_order_detail(session, cast(User, customer))
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_ORDERS_PAGE
        return _render_customer_orders_page(session, cast(User, customer))
    if user_input == "1":
        data = cast(dict[str, Any], session.get("data") or {})
        data["customer_payment_context_order_id"] = _safe_str(data.get("selected_customer_order_id"))
        data["customer_payment_return_state"] = STATE_CUSTOMER_ORDER_DETAIL
        data["customer_payment_show_more"] = False
        session["data"] = data
        session["state"] = STATE_CUSTOMER_PAYMENT_INFO
        return _handle_customer_payment_info(session, "")

    return _render_customer_order_detail(session, cast(User, customer))

def _handle_customer_browse_categories(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    rows = customer_category_rows(limit=6)
    if not user_input:
        if not rows:
            return ussd_continue("Browse Categories\nNo categories available right now.\n0 Back")
        lines = ["Browse Categories"]
        data = cast(dict[str, Any], session.get("data") or {})
        category_values: list[str] = []
        for idx, row in enumerate(rows, start=1):
            category_name = _safe_str(row.get("category"))
            category_values.append(category_name)
            lines.append(f"{idx}. {_short_text(category_name, 16)} ({row.get('item_count')})")
        data["customer_category_values"] = category_values
        session["data"] = data
        lines.append("0 Back")
        return ussd_continue("\n".join(lines))

    if user_input == "0":
        session["state"] = STATE_CUSTOMER_SECURE_MENU
        session["data"] = {}
        return ussd_continue(_customer_secure_menu())

    data = cast(dict[str, Any], session.get("data") or {})
    category_values = cast(list[str], data.get("customer_category_values") or [])
    if user_input.isdigit():
        idx = int(user_input) - 1
        if 0 <= idx < len(category_values):
            data["customer_category_filter"] = category_values[idx]
            data["products_offset"] = 0
            session["data"] = data
            session["state"] = STATE_CUSTOMER_PRODUCTS_PAGE
            return _render_customer_products_page(session, cast(User, customer), banner="Category applied.")

    return _handle_customer_browse_categories(session, "")


def _handle_customer_product_search_input(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    if not user_input:
        return ussd_continue("Search products\nEnter name, category, or code")
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_PRODUCTS_PAGE
        return _render_customer_products_page(session, cast(User, customer))

    data = cast(dict[str, Any], session.get("data") or {})
    data["customer_product_search"] = user_input[:40]
    data["products_offset"] = 0
    session["data"] = data
    session["state"] = STATE_CUSTOMER_PRODUCTS_PAGE
    return _render_customer_products_page(session, cast(User, customer), banner="Search applied.")


def _handle_customer_products_page(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    if not user_input:
        return _render_customer_products_page(session, cast(User, customer))
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_SECURE_MENU
        session["data"] = {}
        return ussd_continue(_customer_secure_menu())
    if _is_next_command(user_input):
        data = cast(dict[str, Any], session.get("data") or {})
        current_offset = _int_or_zero(data.get("products_offset", 0))
        data["products_offset"] = current_offset + 4
        session["data"] = data
        return _render_customer_products_page(session, cast(User, customer))
    if _is_prev_command(user_input):
        data = cast(dict[str, Any], session.get("data") or {})
        data["products_offset"] = max(0, int(data.get("products_offset", 0) or 0) - 4)
        session["data"] = data
        return _render_customer_products_page(session, cast(User, customer))
    if _is_search_command(user_input):
        session["state"] = STATE_CUSTOMER_PRODUCT_SEARCH_INPUT
        return ussd_continue("Search products\nEnter name, category, or code")
    if _is_clear_command(user_input):
        data = cast(dict[str, Any], session.get("data") or {})
        data.pop("customer_product_search", None)
        data.pop("customer_category_filter", None)
        data["products_offset"] = 0
        session["data"] = data
        return _render_customer_products_page(session, cast(User, customer), banner="Filters cleared.")

    data = cast(dict[str, Any], session.get("data") or {})
    page_ids = cast(list[str], data.get("customer_product_page_ids") or [])
    if user_input.isdigit():
        idx = int(user_input) - 1
        if 0 <= idx < len(page_ids):
            data["selected_customer_product_id"] = page_ids[idx]
            session["data"] = data
            session["state"] = STATE_CUSTOMER_PRODUCT_ACTIONS
            return _render_customer_product_actions(session, cast(User, customer))

    return _render_customer_products_page(session, cast(User, customer))


def _handle_customer_product_actions(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    if not user_input:
        return _render_customer_product_actions(session, cast(User, customer))
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_PRODUCTS_PAGE
        return _render_customer_products_page(session, cast(User, customer))
    if user_input == "1":
        detail = _selected_customer_product(session)
        if not detail:
            session["state"] = STATE_CUSTOMER_PRODUCTS_PAGE
            return _render_customer_products_page(session, cast(User, customer), banner="Product no longer available.")
        ok, message = customer_add_to_cart(
            customer=cast(User, customer),
            product_id=_safe_str(detail.get("product_id")),
            qty=Decimal("1"),
        )
        return _render_customer_product_actions(session, cast(User, customer), banner=message)
    if user_input == "2":
        session["state"] = STATE_CUSTOMER_PRODUCT_QTY_INPUT
        detail = _selected_customer_product(session)
        unit_value = _safe_str(detail.get("unit"), "each") if detail else "each"
        return ussd_continue(f"{_customer_enter_amount_label(unit_value)}\nExample: 2 or 1.5\n0 Back")
    return _render_customer_product_actions(session, cast(User, customer))


def _handle_customer_product_qty_input(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    detail = _selected_customer_product(session)
    unit_value = _safe_str(detail.get("unit"), "each") if detail else "each"

    if not user_input:
        return ussd_continue(f"{_customer_enter_amount_label(unit_value)}\nExample: 2 or 1.5\n0 Back")
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_PRODUCT_ACTIONS
        return _render_customer_product_actions(session, cast(User, customer))

    qty = _decimal_from_input(user_input)
    if qty is None:
        return ussd_continue(
            f"Invalid amount. {_customer_enter_amount_label(unit_value)}\nExample: 2 or 1.5\n0 Back"
        )

    if not detail:
        session["state"] = STATE_CUSTOMER_PRODUCTS_PAGE
        return _render_customer_products_page(session, cast(User, customer), banner="Product no longer available.")

    ok, message = customer_add_to_cart(
        customer=cast(User, customer),
        product_id=_safe_str(detail.get("product_id")),
        qty=qty,
    )
    session["state"] = STATE_CUSTOMER_PRODUCT_ACTIONS
    return _render_customer_product_actions(session, cast(User, customer), banner=message)


def _handle_customer_cart_page(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    if not user_input:
        return _render_customer_cart_page(session, cast(User, customer))
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_SECURE_MENU
        session["data"] = {}
        return ussd_continue(_customer_secure_menu())
    if _is_next_command(user_input):
        data = cast(dict[str, Any], session.get("data") or {})
        current_offset = _int_or_zero(data.get("cart_offset", 0))
        data["cart_offset"] = current_offset + 4
        session["data"] = data
        return _render_customer_cart_page(session, cast(User, customer))
    if _is_prev_command(user_input):
        data = cast(dict[str, Any], session.get("data") or {})
        data["cart_offset"] = max(0, int(data.get("cart_offset", 0) or 0) - 4)
        session["data"] = data
        return _render_customer_cart_page(session, cast(User, customer))
    if user_input == "8":
        session["state"] = STATE_CUSTOMER_CHECKOUT_DELIVERY_METHOD
        return ussd_continue("Checkout\n1 Delivery\n2 Pickup\n0 Back")
    if user_input == "9":
        ok, message = customer_clear_cart(cast(User, customer))
        return _render_customer_cart_page(session, cast(User, customer), banner=message)

    data = cast(dict[str, Any], session.get("data") or {})
    page_ids = cast(list[str], data.get("customer_cart_page_ids") or [])
    if user_input.isdigit():
        idx = int(user_input) - 1
        if 0 <= idx < len(page_ids):
            data["selected_customer_cart_item_id"] = page_ids[idx]
            session["data"] = data
            session["state"] = STATE_CUSTOMER_CART_ITEM_ACTIONS
            return _render_customer_cart_item_actions(session, cast(User, customer))

    return _render_customer_cart_page(session, cast(User, customer))


def _handle_customer_cart_item_actions(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    row = _selected_customer_cart_item(session, cast(User, customer))
    if row is None:
        session["state"] = STATE_CUSTOMER_CART_PAGE
        return _render_customer_cart_page(session, cast(User, customer), banner="Cart item not found.")

    if not user_input:
        return _render_customer_cart_item_actions(session, cast(User, customer))
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_CART_PAGE
        return _render_customer_cart_page(session, cast(User, customer))
    if user_input == "1":
        current_qty = _decimal_or_zero(row.get("qty"))
        next_qty = (current_qty + Decimal("1")).quantize(Decimal("0.001"))
        ok, message = customer_update_cart_item_qty(
            customer=cast(User, customer),
            cart_item_id=_safe_str(row.get("cart_item_id")),
            qty=next_qty,
        )
        return _render_customer_cart_item_actions(session, cast(User, customer), banner=message) if ok else _render_customer_cart_item_actions(session, cast(User, customer), banner=message)
    if user_input == "2":
        session["state"] = STATE_CUSTOMER_CART_QTY_INPUT
        return ussd_continue("Enter new cart quantity\n0 removes item")
    if user_input == "3":
        session["state"] = STATE_CUSTOMER_CART_REMOVE_CONFIRM
        return ussd_continue("Remove this item?\n1 Yes\n2 No")

    return _render_customer_cart_item_actions(session, cast(User, customer))


def _handle_customer_cart_qty_input(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    row = _selected_customer_cart_item(session, cast(User, customer))
    if row is None:
        session["state"] = STATE_CUSTOMER_CART_PAGE
        return _render_customer_cart_page(session, cast(User, customer), banner="Cart item not found.")

    if not user_input:
        return ussd_continue("Enter new cart quantity\n0 removes item")

    if user_input == "0":
        ok, message = customer_remove_cart_item(customer=cast(User, customer), cart_item_id=_safe_str(row.get("cart_item_id")))
        session["state"] = STATE_CUSTOMER_CART_PAGE
        return _render_customer_cart_page(session, cast(User, customer), banner=message)

    qty = _decimal_from_input(user_input)
    if qty is None:
        return ussd_continue("Invalid quantity. Enter 2 or 1.5\n0 removes item")

    ok, message = customer_update_cart_item_qty(customer=cast(User, customer), cart_item_id=_safe_str(row.get("cart_item_id")), qty=qty)
    session["state"] = STATE_CUSTOMER_CART_ITEM_ACTIONS
    return _render_customer_cart_item_actions(session, cast(User, customer), banner=message)


def _handle_customer_cart_remove_confirm(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    row = _selected_customer_cart_item(session, cast(User, customer))
    if row is None:
        session["state"] = STATE_CUSTOMER_CART_PAGE
        return _render_customer_cart_page(session, cast(User, customer), banner="Cart item not found.")

    if user_input == "1":
        ok, message = customer_remove_cart_item(customer=cast(User, customer), cart_item_id=_safe_str(row.get("cart_item_id")))
        session["state"] = STATE_CUSTOMER_CART_PAGE
        return _render_customer_cart_page(session, cast(User, customer), banner=message)
    if user_input == "2" or user_input == "0":
        session["state"] = STATE_CUSTOMER_CART_ITEM_ACTIONS
        return _render_customer_cart_item_actions(session, cast(User, customer))
    return ussd_continue("Remove this item?\n1 Yes\n2 No")


def _handle_customer_checkout_delivery_method(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    if not user_input:
        return ussd_continue("Checkout\n1 Delivery\n2 Pickup\n0 Back")
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_CART_PAGE
        return _render_customer_cart_page(session, cast(User, customer))

    data = cast(dict[str, Any], session.get("data") or {})
    if user_input == "1":
        data["checkout_delivery_method"] = "delivery"
        session["data"] = data
        session["state"] = STATE_CUSTOMER_CHECKOUT_ADDRESS
        return ussd_continue("Delivery address\nEnter town / area / landmark\n0 Back")
    if user_input == "2":
        data["checkout_delivery_method"] = "pickup"
        data.pop("checkout_delivery_address", None)
        session["data"] = data
        session["state"] = STATE_CUSTOMER_CHECKOUT_PAYMENT_METHOD
        return ussd_continue("Payment method\n1 EFT / Bank\n2 Cash\n0 Back")

    return ussd_continue("Checkout\n1 Delivery\n2 Pickup\n0 Back")


def _handle_customer_checkout_address(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    if not user_input:
        return ussd_continue("Delivery address\nEnter town / area / landmark\n0 Back")
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_CHECKOUT_DELIVERY_METHOD
        return ussd_continue("Checkout\n1 Delivery\n2 Pickup\n0 Back")

    data = cast(dict[str, Any], session.get("data") or {})
    data["checkout_delivery_address"] = user_input[:80]
    session["data"] = data
    session["state"] = STATE_CUSTOMER_CHECKOUT_PAYMENT_METHOD
    return ussd_continue("Payment method\n1 EFT / Bank\n2 Cash\n0 Back")


def _render_customer_checkout_review(session: dict[str, Any], customer: User) -> UssdResponse:
    """
    Show one lightweight confirmation screen before checkout submission.

    WHY THIS SCREEN EXISTS:
      • helps customers verify the order summary before it is committed
      • reduces accidental submissions on a small USSD interface
      • keeps the journey short by using a single review step instead of
        adding a long wizard
    """
    data = cast(dict[str, Any], session.get("data") or {})
    delivery_method = _safe_str(data.get("checkout_delivery_method"), "delivery")
    payment_method = _safe_str(data.get("checkout_payment_method"), "cash")
    delivery_address = _safe_str(data.get("checkout_delivery_address"))

    snapshot = customer_cart_snapshot(str(getattr(customer, "id")))
    items = cast(list[dict[str, Any]], snapshot.get("items") or [])
    subtotal = snapshot.get("subtotal")

    if not items:
        session["state"] = STATE_CUSTOMER_CART_PAGE
        return _render_customer_cart_page(session, customer, banner="Cart is empty.")

    lines = [
        "Review Order",
        f"Items: {len(items)}",
        f"Subtotal: {_money(subtotal)}",
        f"Delivery: {delivery_method.title()}",
    ]

    if delivery_method == "delivery":
        lines.append(f"Addr: {_short_text(delivery_address, 18, 'not set')}")
        lines.append("Fee: farmer sets later")
    else:
        lines.append("Fee: no delivery fee")

    lines.append(f"Pay: {_short_text(_payment_method_label(payment_method), 18)}")
    lines.extend(["1 Confirm order", "0 Back"])
    return ussd_continue("\n".join(lines))


def _render_customer_payment_info_menu(session: dict[str, Any], customer: User) -> UssdResponse:
    data = cast(dict[str, Any], session.get("data") or {})
    scoped_order_id = _safe_str(data.get("customer_payment_context_order_id") or data.get("selected_customer_order_id"))
    payload = customer_payment_info_payload(str(getattr(customer, "id")), order_id=scoped_order_id)
    show_more = bool(data.get("customer_payment_show_more")) and bool(payload.get("has_more"))
    can_confirm = bool(payload.get("can_confirm"))
    has_reference_submission = bool(payload.get("has_reference_submission"))
    payment_method = _safe_str(payload.get("payment_method"))

    lines = list(cast(list[str], payload.get("detail_lines" if show_more else "summary_lines") or []))
    if can_confirm:
        lines.append(_payment_reference_action_label(payment_method, has_reference_submission=has_reference_submission))
    if bool(payload.get("has_more")):
        lines.append("2 Summary" if show_more else "2 More")
    lines.append("0 Back")
    return ussd_continue("\n".join(lines))

def _handle_customer_checkout_payment_method(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    payment_menu = "Payment method\n1 Cash\n2 Mobile Wallet\n3 EFT / Bank\n0 Back"
    if not user_input:
        return ussd_continue(payment_menu)
    if user_input == "0":
        data = cast(dict[str, Any], session.get("data") or {})
        if _safe_str(data.get("checkout_delivery_method")) == "delivery":
            session["state"] = STATE_CUSTOMER_CHECKOUT_ADDRESS
            return ussd_continue("Delivery address\nEnter town / area / landmark\n0 Back")
        session["state"] = STATE_CUSTOMER_CHECKOUT_DELIVERY_METHOD
        return ussd_continue("Checkout\n1 Delivery\n2 Pickup\n0 Back")

    payment_method = "cash" if user_input == "1" else "mobile_wallet" if user_input == "2" else "eft" if user_input == "3" else ""
    if not payment_method:
        return ussd_continue(payment_menu)

    data = cast(dict[str, Any], session.get("data") or {})
    data["checkout_payment_method"] = payment_method
    session["data"] = data
    session["state"] = STATE_CUSTOMER_CHECKOUT_REVIEW
    return _render_customer_checkout_review(session, cast(User, customer))


def _handle_customer_payment_info(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    data = cast(dict[str, Any], session.get("data") or {})
    scoped_order_id = _safe_str(data.get("customer_payment_context_order_id") or data.get("selected_customer_order_id"))
    payload = customer_payment_info_payload(str(getattr(customer, "id")), order_id=scoped_order_id)
    menu_response = _render_customer_payment_info_menu(session, cast(User, customer))

    if not user_input:
        return menu_response
    if user_input == "0":
        return_state = _safe_str(data.get("customer_payment_return_state"))
        if return_state == STATE_CUSTOMER_ORDER_DETAIL and scoped_order_id:
            session["state"] = STATE_CUSTOMER_ORDER_DETAIL
            data["customer_payment_show_more"] = False
            session["data"] = data
            return _render_customer_order_detail(session, cast(User, customer))
        session["state"] = STATE_CUSTOMER_SECURE_MENU
        session["data"] = {}
        return ussd_continue(_customer_secure_menu())
    if user_input == "2" and bool(payload.get("has_more")):
        data["customer_payment_show_more"] = not bool(data.get("customer_payment_show_more"))
        session["data"] = data
        return _render_customer_payment_info_menu(session, cast(User, customer))
    if user_input == "1" and bool(payload.get("can_confirm")):
        data["customer_payment_show_more"] = False
        data["customer_payment_has_reference_submission"] = bool(payload.get("has_reference_submission"))
        data["selected_customer_payment_order_code"] = _safe_str(payload.get("order_code"))
        data["selected_customer_payment_method"] = _safe_str(payload.get("payment_method"))
        session["data"] = data

        if scoped_order_id:
            session["state"] = STATE_CUSTOMER_PAYMENT_REFERENCE_INPUT
            return ussd_continue(_payment_reference_input_prompt(_safe_str(payload.get("payment_method"))))

        session["state"] = STATE_CUSTOMER_PAYMENT_ORDER_CODE
        return ussd_continue(
            _payment_order_code_prompt(
                has_reference_submission=bool(payload.get("has_reference_submission"))
            )
        )
    return _render_customer_payment_info_menu(session, cast(User, customer))

def _handle_customer_payment_order_code(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    data = cast(dict[str, Any], session.get("data") or {})
    has_reference_submission = bool(data.get("customer_payment_has_reference_submission"))

    if not user_input:
        return ussd_continue(
            _payment_order_code_prompt(has_reference_submission=has_reference_submission)
        )
    if user_input == "0":
        session["state"] = STATE_CUSTOMER_PAYMENT_INFO
        return _render_customer_payment_info_menu(session, cast(User, customer))

    order_row = _customer_find_order_for_payment_reference(str(getattr(customer, "id")), user_input)
    if not order_row:
        return ussd_continue("Order code not found\nEnter valid order code\n0 Back")

    payment_method = _safe_str(order_row.get("payment_method"))
    if not _payment_supports_reference_confirmation(payment_method):
        return ussd_continue("That order uses cash\nEnter another order code\n0 Back")

    data = cast(dict[str, Any], session.get("data") or {})
    data["selected_customer_payment_order_code"] = _short_public_code("O", order_row.get("order_id"))
    data["selected_customer_payment_method"] = payment_method
    session["data"] = data
    session["state"] = STATE_CUSTOMER_PAYMENT_REFERENCE_INPUT

    return ussd_continue(_payment_reference_input_prompt(payment_method))


def _handle_customer_payment_reference_input(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    data = cast(dict[str, Any], session.get("data") or {})
    order_code = _safe_str(data.get("selected_customer_payment_order_code"))
    payment_method = _safe_str(data.get("selected_customer_payment_method"))

    if not user_input:
        return ussd_continue(_payment_reference_input_prompt(payment_method))
    if user_input == "0":
        if _safe_str(data.get("customer_payment_context_order_id")):
            session["state"] = STATE_CUSTOMER_PAYMENT_INFO
            return _render_customer_payment_info_menu(session, cast(User, customer))
        session["state"] = STATE_CUSTOMER_PAYMENT_ORDER_CODE
        return ussd_continue(
            _payment_order_code_prompt(
                has_reference_submission=bool(data.get("customer_payment_has_reference_submission"))
            )
        )

    ok, message = customer_confirm_payment_reference(
        customer=cast(User, customer),
        order_code=order_code,
        payment_reference=user_input,
    )

    data.pop("selected_customer_payment_order_code", None)
    data.pop("selected_customer_payment_method", None)
    data.pop("customer_payment_has_reference_submission", None)
    session["data"] = data

    if ok:
        return _set_result_view(
            session,
            state=STATE_CUSTOMER_RESULT_VIEW,
            message=message,
            back_state=STATE_CUSTOMER_PAYMENT_INFO,
            back_menu=_render_customer_payment_info_menu(session, cast(User, customer)).message,
        )

    return ussd_continue(f"{message}\n{_payment_reference_input_prompt(payment_method)}")

def _handle_customer_secure_menu(session: dict[str, Any], user_input: str) -> UssdResponse:
    customer, guard = _require_authenticated_customer(session)
    if guard is not None:
        return guard

    if not user_input:
        return ussd_continue(_customer_secure_menu())
    if user_input == "0":
        session["state"] = STATE_ROOT
        session["data"] = {}
        return ussd_continue(_welcome_menu())
    if user_input == "7":
        session["is_authenticated"] = False
        session["user_id"] = None
        session["state"] = STATE_CUSTOMER_MENU
        session["data"] = {}
        return ussd_end("Logged out successfully.")
    if user_input == "1":
        session["state"] = STATE_CUSTOMER_PRODUCT_SEARCH_INPUT
        return ussd_continue("Search products\nEnter name, category, or code")
    if user_input == "2":
        session["state"] = STATE_CUSTOMER_BROWSE_CATEGORIES
        session["data"] = {}
        return _handle_customer_browse_categories(session, "")
    if user_input == "3":
        session["state"] = STATE_CUSTOMER_CART_PAGE
        session["data"] = {"cart_offset": 0}
        return _render_customer_cart_page(session, cast(User, customer))
    if user_input == "4":
        session["state"] = STATE_CUSTOMER_ORDERS_PAGE
        session["data"] = {"orders_offset": 0}
        return _render_customer_orders_page(session, cast(User, customer))
    if user_input == "5":
        data = cast(dict[str, Any], session.get("data") or {})
        data.pop("customer_payment_context_order_id", None)
        data.pop("customer_payment_return_state", None)
        data["customer_payment_show_more"] = False
        session["state"] = STATE_CUSTOMER_PAYMENT_INFO
        session["data"] = data
        return _handle_customer_payment_info(session, "")
    if user_input == "6":
        return _set_paged_result_view(
            session,
            state=STATE_CUSTOMER_HELP_VIEW,
            lines=[
                "Customer Help",
                "1 Search products and add to cart.",
                "3 My cart for checkout.",
                "Use EFT ref = order code.",
                "Submit your payment ref in Payment Info.",
            ],
        )
    return ussd_continue(_customer_secure_menu())


# ---------------------------------------------------------------------------
# Main public entrypoint
# ---------------------------------------------------------------------------
def process_ussd_callback(
    *,
    session_id: str,
    service_code: str,
    phone_number: str,
    text_value: str,
) -> UssdResponse:
    session = _load_session(session_id, phone_number, service_code)
    current_text = _safe_str(text_value)

    # Recover long public registrations when a provider timeout expires the live
    # session before the user reaches the final USSD PIN step.
    _maybe_resume_registration(session, current_text)

    previous_text = _safe_str(session.get("last_text"))
    new_input = _extract_new_input(previous_text, current_text)

    logger.info(
        "[USSD][CALLBACK] session=%s phone=%s state=%s text=%s new_input=%s",
        session_id,
        normalize_phone_number(phone_number),
        session.get("state"),
        current_text,
        new_input,
    )

    try:
        state = _safe_str(session.get("state"), STATE_ROOT)

        if state == STATE_ROOT:
            response = _handle_root(session, new_input)
        elif state == STATE_FARMER_MENU:
            response = _handle_farmer_menu(session, new_input)
        elif state == STATE_FARMER_REGISTER_NAME:
            response = _handle_farmer_register_name(session, new_input)
        elif state == STATE_FARMER_REGISTER_EMAIL:
            response = _handle_farmer_register_email(session, new_input)
        elif state == STATE_FARMER_REGISTER_WEB_PASSWORD:
            response = _handle_farmer_register_web_password(session, new_input)
        elif state == STATE_FARMER_REGISTER_WEB_PASSWORD_CONFIRM:
            response = _handle_farmer_register_web_password_confirm(session, new_input)
        elif state == STATE_FARMER_REGISTER_PIN:
            response = _handle_farmer_register_pin(session, new_input)
        elif state == STATE_FARMER_LOGIN_PIN:
            response = _handle_farmer_login_pin(session, new_input)
        elif state == STATE_FARMER_SECURE_MENU:
            response = _handle_farmer_secure_menu(session, new_input)
        elif state == STATE_FARMER_BANK_PROFILE_MENU:
            response = _handle_farmer_bank_profile_menu(session, new_input)
        elif state == STATE_FARMER_BANK_PROFILE_BANK:
            response = _handle_farmer_bank_profile_bank(session, new_input)
        elif state == STATE_FARMER_BANK_PROFILE_ACCOUNT_NAME:
            response = _handle_farmer_bank_profile_account_name(session, new_input)
        elif state == STATE_FARMER_BANK_PROFILE_ACCOUNT_NUMBER:
            response = _handle_farmer_bank_profile_account_number(session, new_input)
        elif state == STATE_FARMER_BANK_PROFILE_BRANCH_CODE:
            response = _handle_farmer_bank_profile_branch_code(session, new_input)
        elif state == STATE_FARMER_BANK_PROFILE_BRANCH_TOWN:
            response = _handle_farmer_bank_profile_branch_town(session, new_input)
        elif state == STATE_FARMER_BANK_PROFILE_PAYMENT_REF:
            response = _handle_farmer_bank_profile_payment_ref(session, new_input)
        elif state == STATE_FARMER_PRODUCTS_PAGE:
            response = _handle_farmer_products_page(session, new_input)
        elif state == STATE_FARMER_PRODUCT_SEARCH_INPUT:
            # Search input is a dedicated screen. Without this route, the
            # callback falls through to the root menu and the farmer never sees
            # filtered product results.
            response = _handle_farmer_product_search_input(session, new_input)
        elif state == STATE_FARMER_PRODUCT_ACTIONS:
            response = _handle_farmer_product_actions(session, new_input)
        elif state == STATE_FARMER_PRODUCT_REJECTION_VIEW:
            response = _handle_farmer_product_rejection_view(session, new_input)
        elif state == STATE_FARMER_PRODUCT_APPEAL_INPUT:
            response = _handle_farmer_product_appeal_input(session, new_input)
        elif state == STATE_FARMER_PRODUCT_UPDATE_MENU:
            response = _handle_farmer_product_update_menu(session, new_input)
        elif state == STATE_FARMER_PRODUCT_UPDATE_NAME:
            response = _handle_farmer_product_update_name(session, new_input)
        elif state == STATE_FARMER_PRODUCT_UPDATE_DESCRIPTION:
            response = _handle_farmer_product_update_description(session, new_input)
        elif state == STATE_FARMER_PRODUCT_UPDATE_CATEGORY:
            response = _handle_farmer_product_update_category(session, new_input)
        elif state == STATE_FARMER_PRODUCT_UPDATE_PRICE:
            response = _handle_farmer_product_update_price(session, new_input)
        elif state == STATE_FARMER_PRODUCT_UPDATE_QTY:
            response = _handle_farmer_product_update_qty(session, new_input)
        elif state == STATE_FARMER_PRODUCT_UPDATE_UNIT:
            response = _handle_farmer_product_update_unit(session, new_input)
        elif state == STATE_FARMER_PRODUCT_DELETE_CONFIRM:
            response = _handle_farmer_product_delete_confirm(session, new_input)
        elif state == STATE_FARMER_ADD_PRODUCT_NAME:
            response = _handle_farmer_add_product_name(session, new_input)
        elif state == STATE_FARMER_ADD_PRODUCT_DESCRIPTION:
            response = _handle_farmer_add_product_description(session, new_input)
        elif state == STATE_FARMER_ADD_PRODUCT_CATEGORY:
            response = _handle_farmer_add_product_category(session, new_input)
        elif state == STATE_FARMER_ADD_PRODUCT_PRICE:
            response = _handle_farmer_add_product_price(session, new_input)
        elif state == STATE_FARMER_ADD_PRODUCT_QTY:
            response = _handle_farmer_add_product_qty(session, new_input)
        elif state == STATE_FARMER_ADD_PRODUCT_UNIT:
            response = _handle_farmer_add_product_unit(session, new_input)
        elif state == STATE_FARMER_ORDERS_PAGE:
            response = _handle_farmer_orders_page(session, new_input)
        elif state == STATE_FARMER_PAYMENT_CONFIRMATIONS_PAGE:
            response = _handle_farmer_payment_confirmations_page(session, new_input)
        elif state == STATE_FARMER_PAYMENT_CONFIRMATION_ACTIONS:
            response = _handle_farmer_payment_confirmation_actions(session, new_input)
        elif state == STATE_FARMER_ORDER_SEARCH_INPUT:
            # Same fix as product search: route the free-text search screen
            # back into the correct handler instead of dropping to the root menu.
            response = _handle_farmer_order_search_input(session, new_input)
        elif state == STATE_FARMER_ORDER_ACTIONS:
            response = _handle_farmer_order_actions(session, new_input)
        elif state == STATE_FARMER_ORDER_DELIVERY_FEE_INPUT:
            response = _handle_farmer_order_delivery_fee_input(session, new_input)
        elif state == STATE_FARMER_ORDER_READY_FOR_PAYMENT_CONFIRM:
            response = _handle_farmer_order_ready_for_payment_confirm(session, new_input)
        elif state == STATE_FARMER_ORDER_DELIVERY_MENU:
            response = _handle_farmer_order_delivery_menu(session, new_input)
        elif state in {
            STATE_FARMER_MONTHLY_SALES_VIEW,
            STATE_FARMER_STOCK_ALERTS_VIEW,
            STATE_FARMER_BANK_PROFILE_VIEW,
            STATE_FARMER_HELP_VIEW,
            STATE_FARMER_RESULT_VIEW,
            STATE_FARMER_PRODUCT_VIEW,
            STATE_FARMER_PRODUCT_DEMAND_VIEW,
            STATE_FARMER_PRODUCT_REJECTION_VIEW,
            STATE_FARMER_ORDER_PAYMENT_VIEW,
        }:
            response = _handle_backable_view(session, back_state=STATE_FARMER_SECURE_MENU, back_menu=_farmer_secure_menu(), user_input=new_input)

        elif state == STATE_CUSTOMER_MENU:
            response = _handle_customer_menu(session, new_input)
        elif state == STATE_CUSTOMER_REGISTER_NAME:
            response = _handle_customer_register_name(session, new_input)
        elif state == STATE_CUSTOMER_REGISTER_EMAIL:
            response = _handle_customer_register_email(session, new_input)
        elif state == STATE_CUSTOMER_REGISTER_WEB_PASSWORD:
            response = _handle_customer_register_web_password(session, new_input)
        elif state == STATE_CUSTOMER_REGISTER_WEB_PASSWORD_CONFIRM:
            response = _handle_customer_register_web_password_confirm(session, new_input)
        elif state == STATE_CUSTOMER_REGISTER_PIN:
            response = _handle_customer_register_pin(session, new_input)
        elif state == STATE_CUSTOMER_LOGIN_PIN:
            response = _handle_customer_login_pin(session, new_input)
        elif state == STATE_CUSTOMER_SECURE_MENU:
            response = _handle_customer_secure_menu(session, new_input)
        elif state == STATE_CUSTOMER_BROWSE_CATEGORIES:
            response = _handle_customer_browse_categories(session, new_input)
        elif state == STATE_CUSTOMER_PRODUCT_SEARCH_INPUT:
            response = _handle_customer_product_search_input(session, new_input)
        elif state == STATE_CUSTOMER_PRODUCTS_PAGE:
            response = _handle_customer_products_page(session, new_input)
        elif state == STATE_CUSTOMER_PRODUCT_ACTIONS:
            response = _handle_customer_product_actions(session, new_input)
        elif state == STATE_CUSTOMER_PRODUCT_QTY_INPUT:
            response = _handle_customer_product_qty_input(session, new_input)
        elif state == STATE_CUSTOMER_CART_PAGE:
            response = _handle_customer_cart_page(session, new_input)
        elif state == STATE_CUSTOMER_CART_ITEM_ACTIONS:
            response = _handle_customer_cart_item_actions(session, new_input)
        elif state == STATE_CUSTOMER_CART_QTY_INPUT:
            response = _handle_customer_cart_qty_input(session, new_input)
        elif state == STATE_CUSTOMER_CART_REMOVE_CONFIRM:
            response = _handle_customer_cart_remove_confirm(session, new_input)
        elif state == STATE_CUSTOMER_CHECKOUT_DELIVERY_METHOD:
            response = _handle_customer_checkout_delivery_method(session, new_input)
        elif state == STATE_CUSTOMER_CHECKOUT_ADDRESS:
            response = _handle_customer_checkout_address(session, new_input)
        elif state == STATE_CUSTOMER_CHECKOUT_PAYMENT_METHOD:
            response = _handle_customer_checkout_payment_method(session, new_input)
        elif state == STATE_CUSTOMER_CHECKOUT_REVIEW:
            response = _handle_customer_checkout_review(session, new_input)
        elif state == STATE_CUSTOMER_ORDERS_PAGE:
            response = _handle_customer_orders_page(session, new_input)
        elif state == STATE_CUSTOMER_ORDER_DETAIL:
            response = _handle_customer_order_detail(session, new_input)
        elif state == STATE_CUSTOMER_PAYMENT_INFO:
            response = _handle_customer_payment_info(session, new_input)
        elif state == STATE_CUSTOMER_PAYMENT_ORDER_CODE:
            response = _handle_customer_payment_order_code(session, new_input)
        elif state == STATE_CUSTOMER_PAYMENT_REFERENCE_INPUT:
            response = _handle_customer_payment_reference_input(session, new_input)
        elif state in {STATE_CUSTOMER_HELP_VIEW, STATE_CUSTOMER_RESULT_VIEW}:
            response = _handle_backable_view(session, back_state=STATE_CUSTOMER_SECURE_MENU, back_menu=_customer_secure_menu(), user_input=new_input)
        else:
            session["state"] = STATE_ROOT
            response = ussd_continue(_welcome_menu())

    except Exception as exc:
        db.session.rollback()
        logger.exception("[USSD] Callback processing failed: %s", exc)
        try:
            _log_activity(
                session=session,
                event_type="error",
                user_input=new_input,
                message_text="We could not process your request. Please try again.",
                metadata={"error": str(exc)},
            )
        except Exception:
            pass
        _close_session(_safe_str(session.get("session_id")))
        return ussd_end("We could not process your request. Please try again.")

    if bool(session.get("is_authenticated")) and _safe_str(session.get("user_id")):
        _touch_user_auth_timestamps(user_id=session.get("user_id"), update_login=False)

    session["last_text"] = current_text
    _persist_runtime_state_and_logs(session=session, response=response, new_input=new_input)

    if response.prefix == USSD_END:
        _close_session(_safe_str(session.get("session_id")))

    return response


def _is_terminal_ussd_event(payload: dict[str, Any]) -> bool:
    """
    Only treat clearly terminal provider events as session-ending events.

    Africa's Talking can emit non-terminal events during an active session.
    Closing the session for every event causes normal menu navigation to
    appear as if the session expired unexpectedly.
    """
    values = [
        _safe_str(payload.get("eventType")).lower(),
        _safe_str(payload.get("event_type")).lower(),
        _safe_str(payload.get("type")).lower(),
        _safe_str(payload.get("status")).lower(),
        _safe_str(payload.get("sessionStatus")).lower(),
        _safe_str(payload.get("session_status")).lower(),
        _safe_str(payload.get("reason")).lower(),
    ]

    normalized = [value.replace("-", "_").replace(" ", "_") for value in values if value]

    terminal_exact = {
        "end",
        "ended",
        "complete",
        "completed",
        "close",
        "closed",
        "abort",
        "aborted",
        "timeout",
        "timed_out",
        "expired",
        "session_end",
        "session_ended",
    }

    for value in normalized:
        if value in terminal_exact:
            return True

    is_active = _safe_str(payload.get("isActive") or payload.get("is_active")).lower()
    if is_active in {"false", "0", "no"}:
        return True

    return False


def handle_ussd_event(payload: dict[str, Any]) -> None:
    session_id = _safe_str(payload.get("sessionId") or payload.get("session_id"))
    service_code = _safe_str(payload.get("serviceCode") or payload.get("service_code"))
    phone_number = normalize_phone_number(payload.get("phoneNumber") or payload.get("phone_number"))

    logger.info(
        "[USSD][EVENT] session=%s serviceCode=%s phone=%s payload=%s",
        session_id,
        service_code,
        phone_number,
        payload,
    )

    if not session_id:
        return

    session = _load_session(session_id, phone_number, service_code)
    is_terminal = _is_terminal_ussd_event(payload)

    try:
        _log_activity(
            session=session,
            event_type="event",
            user_input="",
            message_text="USSD event received",
            metadata={**payload, "_is_terminal": is_terminal},
        )
    except Exception as exc:
        logger.warning("[USSD] Non-critical event logging failed: %s", exc)

    if is_terminal:
        _close_session(session_id)

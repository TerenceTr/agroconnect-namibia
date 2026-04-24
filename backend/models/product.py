# ====================================================================
# backend/models/product.py — Product Model (C1 + Moderation + Query-safe)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Core Product ORM model (table: products) with:
#   • C1 unit/pack fields (unit, pack_size, pack_unit)
#   • Moderation workflow (pending/available/rejected)
#   • SLA timestamps (submitted_at, status_updated_at)
#   • Query-safe aliases via synonym() (id/name/stock/farmer_id)
#
# OPTION 1 (BUSINESS RULES) SUPPORTED:
#   ✅ New products default to status='pending' (admin approval required)
#   ✅ Approved products use status='available' (visible to customers)
#   ✅ Rejected products use status='rejected' (hidden, reason shown)
#   ✅ Farmer edits to key fields auto-reset to 'pending' (SQLAlchemy event)
#
# MODERATION DIFF + SLA SUPPORT:
#   ✅ moderation_snapshot: baseline of fields at last approval
#   ✅ moderation_changes: changed fields + before/after values for admin review
#   ✅ submitted_at: SLA clock start (does NOT restart if already pending)
#   ✅ status_updated_at: timestamp for any status transition
#
# IMPORTANT HARDENING (THIS VERSION):
#   ✅ Admin edits can bypass auto-reset by setting: product._moderation_actor = "admin"
#   ✅ Better “previous_status” capture using SQLAlchemy history
#   ✅ before_insert sets submitted_at/status_updated_at best-effort (DB defaults still apply)
#   ✅ Pyright: safe inspect(target) narrowing (fixes "attrs on None")
# ====================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, Optional, Protocol, TYPE_CHECKING, cast

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
    JSON,
    text,
    event,
    inspect,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym
from sqlalchemy.sql import func

from backend.database.db import db

if TYPE_CHECKING:
    from .user import User
    from .rating import Rating
    from .ai_stock_alert import AIStockAlert
    from .market_trend import MarketTrend
    from .order_item import OrderItem


# ----------------------------------------------------------------------------
# Moderation-sensitive fields:
# If a FARMER changes any of these, the product must return to PENDING.
# ----------------------------------------------------------------------------
MODERATION_SENSITIVE_FIELDS = {
    "product_name",
    "description",
    "category",
    "price",
    "unit",
    "pack_size",
    "pack_unit",
    "image_url",
}


def _jsonable(v: Any) -> Any:
    """Convert non-JSON-safe types (Decimal/UUID/datetime) into JSON-safe values."""
    if v is None:
        return None
    if isinstance(v, uuid.UUID):
        return str(v)
    if isinstance(v, Decimal):
        return float(v)
    if isinstance(v, datetime):
        return v.isoformat()
    return v


# ---- Pyright-friendly inspected-state protocol ----
class _HasAttrs(Protocol):
    attrs: Any


def _get_state(obj: Any) -> Optional[_HasAttrs]:
    """
    Pylance/Pyright fix:
    SQLAlchemy stubs can type inspect(...) as Optional[...] which makes `.attrs`
    look unsafe. Narrow safely here.
    """
    try:
        st = inspect(obj)
        if st is None or not hasattr(st, "attrs"):
            return None
        return cast(_HasAttrs, st)
    except Exception:
        return None


def _make_diff(state: _HasAttrs, fields: set[str], target: Any) -> Dict[str, Any]:
    """
    Build structured diff from SQLAlchemy history:
      { changed_fields: [...], diff: { field: { from, to } } }
    """
    changed: list[str] = []
    diff: Dict[str, Any] = {}

    for f in fields:
        if f not in state.attrs:
            continue

        hist = state.attrs[f].history
        if not hist.has_changes():
            continue

        changed.append(f)

        before = hist.deleted[0] if hist.deleted else None
        after = hist.added[0] if hist.added else getattr(target, f, None)

        diff[f] = {"from": _jsonable(before), "to": _jsonable(after)}

    return {"changed_fields": changed, "diff": diff}


class Product(db.Model):  # type: ignore[misc]
    """
    Product listing created/owned by a farmer.

    Admin bypass:
      • Admin routes may set `product._moderation_actor = "admin"` before commit
        to avoid triggering re-moderation when an admin edits sensitive fields.
    """

    __tablename__ = "products"

    # ----------------------------------------------------------------
    # Primary key
    # ----------------------------------------------------------------
    product_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # ----------------------------------------------------------------
    # Owner FK (farmer user)
    # ----------------------------------------------------------------
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    # ----------------------------------------------------------------
    # Product info
    # ----------------------------------------------------------------
    product_name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    price: Mapped[Decimal] = mapped_column(
        Numeric(10, 2),
        nullable=False,
        default=Decimal("0.00"),
        server_default=text("0"),
    )

    quantity: Mapped[Decimal] = mapped_column(
        Numeric(12, 3),
        nullable=False,
        default=Decimal("0"),
        server_default=text("0"),
    )

    image_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ----------------------------------------------------------------
    # Moderation / visibility
    # Option 1 canonical statuses:
    #   pending -> available -> rejected
    # (We keep compatibility with older code that may still use 'approved')
    # ----------------------------------------------------------------
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        server_default=text("'pending'"),
        index=True,
    )

    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    reviewed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)

    # ----------------------------------------------------------------
    # Audit + SLA timestamps
    # created_at/updated_at are general audit fields.
    # status_updated_at tracks any status transition.
    # submitted_at is the SLA clock start when entering pending from non-pending.
    # ----------------------------------------------------------------
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        index=True,
    )

    status_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    # Best-effort “who edited last” (routes should set last_edited_by)
    last_edited_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    last_edited_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)

    # Moderation baseline + diff (for admin review UI)
    moderation_snapshot: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    moderation_changes: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # ----------------------------------------------------------------
    # C1 Unit system
    # ----------------------------------------------------------------
    unit: Mapped[str] = mapped_column(String(20), nullable=False, server_default=text("'each'"))
    pack_size: Mapped[Optional[Decimal]] = mapped_column(Numeric(12, 3), nullable=True)
    pack_unit: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # ----------------------------------------------------------------
    # Compatibility aliases (query-safe)
    # ----------------------------------------------------------------
    id = synonym("product_id")
    name = synonym("product_name")
    stock = synonym("quantity")
    farmer_id = synonym("user_id")

    # ----------------------------------------------------------------
    # Relationships
    # ----------------------------------------------------------------
    farmer: Mapped["User"] = relationship(
        "User",
        back_populates="products",
        foreign_keys=[user_id],
        passive_deletes=True,
    )

    reviewer: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys=[reviewed_by],
        lazy="selectin",
        viewonly=True,
    )

    ratings: Mapped[list["Rating"]] = relationship(
        "Rating",
        back_populates="product",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    ai_stock_alerts: Mapped[list["AIStockAlert"]] = relationship(
        "AIStockAlert",
        back_populates="product",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    market_trends: Mapped[list["MarketTrend"]] = relationship(
        "MarketTrend",
        back_populates="product",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    order_items: Mapped[list["OrderItem"]] = relationship(
        "OrderItem",
        back_populates="product",
        lazy="select",
        passive_deletes=True,
    )

    # ----------------------------------------------------------------
    # Moderation helpers
    # ----------------------------------------------------------------
    def build_moderation_snapshot(self) -> dict[str, Any]:
        """Baseline snapshot used after admin approval."""
        return {
            "product_name": self.product_name,
            "description": self.description,
            "category": self.category,
            "price": _jsonable(self.price),
            "unit": self.unit,
            "pack_size": _jsonable(self.pack_size),
            "pack_unit": self.pack_unit,
            "image_url": self.image_url,
        }

    def to_dict(self) -> dict[str, Any]:
        """Stable, frontend-friendly serialization."""
        return {
            "id": str(self.product_id),
            "product_id": str(self.product_id),
            "user_id": str(self.user_id),
            "farmer_id": str(self.user_id),
            "name": self.product_name,
            "product_name": self.product_name,
            "description": self.description,
            "category": self.category,
            "price": float(self.price or 0),
            "quantity": float(self.quantity or 0),
            "stock": float(self.quantity or 0),
            "unit": self.unit,
            "pack_size": float(self.pack_size) if self.pack_size is not None else None,
            "pack_unit": self.pack_unit,
            "image_url": self.image_url,
            "status": self.status,
            "rejection_reason": self.rejection_reason,
            "reviewed_by": str(self.reviewed_by) if self.reviewed_by else None,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "status_updated_at": self.status_updated_at.isoformat() if self.status_updated_at else None,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
            "last_edited_by": str(self.last_edited_by) if self.last_edited_by else None,
            "last_edited_at": self.last_edited_at.isoformat() if self.last_edited_at else None,
            "moderation_snapshot": self.moderation_snapshot,
            "moderation_changes": self.moderation_changes,
        }


# ----------------------------------------------------------------------------
# Indexes
# ----------------------------------------------------------------------------
Index("ix_products_owner_name", Product.user_id, Product.product_name)
Index("ix_products_status_submitted", Product.status, Product.submitted_at)
Index("ix_products_status_updated", Product.status, Product.status_updated_at)


# ----------------------------------------------------------------------------
# Events
# ----------------------------------------------------------------------------
@event.listens_for(Product, "before_insert", propagate=True)
def _product_before_insert(mapper, connection, target: "Product"):  # noqa: ARG001
    """Best-effort defaults in Python (DB server_default still applies)."""
    now = datetime.utcnow()

    # If caller didn't set these, ensure they exist for SLA/reporting.
    if not getattr(target, "status_updated_at", None):
        target.status_updated_at = now
    if not getattr(target, "submitted_at", None):
        target.submitted_at = now


@event.listens_for(Product, "before_update", propagate=True)
def _product_before_update(mapper, connection, target: "Product"):  # noqa: ARG001
    """
    Farmer edits of moderation-sensitive fields force status back to 'pending'
    (unless admin bypass is set).

    Admin bypass:
      set target._moderation_actor = "admin" before commit.
    """
    now = datetime.utcnow()

    try:
        state = _get_state(target)
        if state is None:
            return  # Pyright-safe: no `.attrs` on None

        # ------------------------------------------------------------
        # (A) Status transition timestamps (admin OR farmer)
        # ------------------------------------------------------------
        if "status" in state.attrs and state.attrs.status.history.has_changes():
            old_status = state.attrs.status.history.deleted[0] if state.attrs.status.history.deleted else None
            new_status = state.attrs.status.history.added[0] if state.attrs.status.history.added else target.status

            # Always track status transition time.
            target.status_updated_at = now

            # SLA clock starts when entering pending from non-pending.
            if str(new_status or "").lower() == "pending" and str(old_status or "").lower() != "pending":
                target.submitted_at = now

            # Best-effort: if moving to available/approved, set moderation baseline automatically.
            if str(new_status or "").lower() in {"available", "approved"}:
                try:
                    target.moderation_snapshot = target.build_moderation_snapshot()  # type: ignore[assignment]
                    target.moderation_changes = None  # type: ignore[assignment]
                except Exception:
                    pass

        # ------------------------------------------------------------
        # (B) Sensitive edits -> re-moderation (FARMER edits only)
        # ------------------------------------------------------------
        actor = getattr(target, "_moderation_actor", None)
        if str(actor or "").lower() == "admin":
            return

        diff_payload = _make_diff(state, MODERATION_SENSITIVE_FIELDS, target)
        changed_fields = diff_payload.get("changed_fields") or []
        if not changed_fields:
            return

        # Track edit time (routes should also set last_edited_by).
        target.last_edited_at = now

        # Determine previous status BEFORE we enforce pending.
        prev_status_from_history = None
        if "status" in state.attrs and state.attrs.status.history.deleted:
            prev_status_from_history = state.attrs.status.history.deleted[0]
        previous_status = prev_status_from_history if prev_status_from_history is not None else target.status
        was_pending = str(previous_status or "").lower() == "pending"

        # Enforce pending workflow.
        target.status = "pending"

        # SLA clock does NOT restart if it was already pending.
        if not was_pending:
            target.submitted_at = now
            target.status_updated_at = now

        # Clear review state (so admin sees it as needing review).
        prev_rejection = target.rejection_reason
        target.reviewed_at = None
        target.reviewed_by = None
        target.rejection_reason = None

        # Store diff for admin UI.
        target.moderation_changes = {
            "changed_fields": changed_fields,
            "diff": diff_payload.get("diff") or {},
            "edited_at": now.isoformat(),
            "pending_reason": "edited_by_farmer",
            "previous_status": _jsonable(previous_status),
            "previous_rejection_reason": _jsonable(prev_rejection),
        }

    except Exception:
        return

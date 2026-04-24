# ============================================================================
# backend/models/farmer_payment_profile.py — Farmer EFT / Bank Details Profile
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Stores reusable farmer bank/EFT details outside `users` and `payments`.
#
# WHY THIS EXISTS:
#   • Clean separation of concerns
#   • One farmer -> one payment profile
#   • Customer checkout can read farmer EFT details safely
#   • Farmer can manage payment details from Settings
#
# IMPORTANT:
#   This table is optional until the migration is applied.
#
# PYRIGHT / DEV-SAFE NOTES:
#   • Keep this model simple and explicit
#   • Avoid extra ORM complexity not required by current routes
#   • We intentionally do NOT rely on a `user` relationship here because the
#     current EFT routes and orders flow only need the stored payment fields
# ============================================================================
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.db import db


class FarmerPaymentProfile(db.Model):  # type: ignore[misc]
    """
    Reusable farmer EFT / bank details.

    DESIGN:
      • Exactly one row per farmer
      • Safe to read from order/checkout flows
      • Independent from payment transaction rows
    """

    __tablename__ = "farmer_payment_profiles"

    # -------------------------------------------------------------------------
    # Primary key
    # -------------------------------------------------------------------------
    profile_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    # -------------------------------------------------------------------------
    # Farmer owner
    # -------------------------------------------------------------------------
    # One farmer -> one payment profile
    farmer_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    # -------------------------------------------------------------------------
    # EFT / bank details shown to customers
    # -------------------------------------------------------------------------
    bank_name: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    account_name: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    account_number: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)
    branch_code: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    payment_instructions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # -------------------------------------------------------------------------
    # Control flags
    # -------------------------------------------------------------------------
    # use_for_eft:
    #   Whether these details should be exposed for EFT / bank transfer orders
    use_for_eft: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )

    # is_active:
    #   Whether the payment profile is enabled for current use
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )

    # -------------------------------------------------------------------------
    # Timestamps
    # -------------------------------------------------------------------------
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        server_default=text("now()"),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        server_default=text("now()"),
    )

    # -------------------------------------------------------------------------
    # Small model helpers
    # -------------------------------------------------------------------------
    def is_complete(self) -> bool:
        """
        Return True when the minimum EFT fields required for customer payment
        are present.
        """
        return bool(
            (self.bank_name or "").strip()
            and (self.account_name or "").strip()
            and (self.account_number or "").strip()
        )

    def to_dict(self) -> dict[str, object]:
        """
        Stable API serializer used by:
          • farmer settings page
          • customer checkout/order history
          • order routes exposing bank details
        """
        return {
            "profile_id": str(self.profile_id),
            "farmer_id": str(self.farmer_id),
            "bank_name": self.bank_name,
            "account_name": self.account_name,
            "account_number": self.account_number,
            "branch_code": self.branch_code,
            "payment_instructions": self.payment_instructions,
            "use_for_eft": bool(self.use_for_eft),
            "is_active": bool(self.is_active),
            "is_complete": self.is_complete(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            "FarmerPaymentProfile("
            f"profile_id={self.profile_id}, "
            f"farmer_id={self.farmer_id}, "
            f"use_for_eft={self.use_for_eft}, "
            f"is_active={self.is_active}"
            ")"
        )
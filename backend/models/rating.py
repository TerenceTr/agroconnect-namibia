# ============================================================================
# backend/models/rating.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Verified review + governance model for AgroConnect.
#
# IMPORTANT FIXES IN THIS VERSION:
#   ✅ Keeps review workflow relationships registry-safe
#   ✅ Avoids fragile mapper-time string order_by expressions
#   ✅ Keeps explicit author/moderator foreign key wiring
#   ✅ Keeps Phase 1–4 review/governance fields
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym
from sqlalchemy.sql import func

from backend.database.db import db

if TYPE_CHECKING:
    from .order import Order
    from .order_item import OrderItem
    from .product import Product
    from .rating_flag import RatingFlag
    from .rating_response import RatingResponse
    from .review_issue_link import ReviewIssueLink
    from .review_policy_action import ReviewPolicyAction
    from .user import User


def utc_now_naive() -> datetime:
    return datetime.utcnow()


class Rating(db.Model):
    __tablename__ = "ratings"

    __table_args__ = (
        UniqueConstraint("user_id", "order_item_id", name="uq_ratings_user_order_item"),
    )

    # ---------------------------------------------------------------------
    # Primary key
    # ---------------------------------------------------------------------
    id: Mapped[uuid.UUID] = mapped_column(
        "rating_id",
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    rating_id = synonym("id")

    # ---------------------------------------------------------------------
    # Foreign keys
    # ---------------------------------------------------------------------
    product_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("products.product_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    order_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("orders.order_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    order_item_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("order_items.order_item_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    moderated_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ---------------------------------------------------------------------
    # Review content
    # ---------------------------------------------------------------------
    rating_score: Mapped[int] = mapped_column(Integer, nullable=False)
    comments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    verified_purchase: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        index=True,
    )

    issue_tag: Mapped[Optional[str]] = mapped_column(Text, nullable=True, index=True)

    resolution_status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="open",
        server_default="open",
        index=True,
    )

    first_farmer_response_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=False),
        nullable=True,
    )
    last_farmer_response_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=False),
        nullable=True,
    )

    moderation_status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="visible",
        server_default="visible",
        index=True,
    )
    moderation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    moderation_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    moderated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=False),
        nullable=True,
    )
    policy_action: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        default=utc_now_naive,
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    # ---------------------------------------------------------------------
    # Relationships
    # ---------------------------------------------------------------------
    product: Mapped["Product"] = relationship(
        "Product",
        back_populates="ratings",
        lazy="selectin",
    )

    user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys=[user_id],
        back_populates="ratings",
        lazy="selectin",
    )

    order: Mapped[Optional["Order"]] = relationship(
        "Order",
        lazy="selectin",
    )

    order_item: Mapped[Optional["OrderItem"]] = relationship(
        "OrderItem",
        lazy="selectin",
    )

    moderator: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys=[moderated_by],
        back_populates="moderated_ratings",
        lazy="selectin",
    )

    responses: Mapped[list["RatingResponse"]] = relationship(
        "RatingResponse",
        back_populates="rating",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    flags: Mapped[list["RatingFlag"]] = relationship(
        "RatingFlag",
        back_populates="rating",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    policy_actions: Mapped[list["ReviewPolicyAction"]] = relationship(
        "ReviewPolicyAction",
        back_populates="rating",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    issue_links: Mapped[list["ReviewIssueLink"]] = relationship(
        "ReviewIssueLink",
        back_populates="rating",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    # ---------------------------------------------------------------------
    # Serialization
    # ---------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        score = int(self.rating_score)

        public_responses = sorted(
            [
                response.to_dict()
                for response in getattr(self, "responses", [])
                if bool(getattr(response, "is_public", True))
            ],
            key=lambda item: str(item.get("created_at") or ""),
        )

        issue_links = sorted(
            [link.to_dict() for link in getattr(self, "issue_links", [])],
            key=lambda item: (
                0 if bool(item.get("is_primary")) else 1,
                str(item.get("created_at") or ""),
            ),
        )

        flags = sorted(
            [flag.to_dict() for flag in getattr(self, "flags", [])],
            key=lambda item: str(item.get("created_at") or ""),
            reverse=True,
        )

        policy_actions = sorted(
            [action.to_dict() for action in getattr(self, "policy_actions", [])],
            key=lambda item: str(item.get("created_at") or ""),
            reverse=True,
        )

        return {
            "id": str(self.id),
            "rating_id": str(self.id),
            "order_id": str(self.order_id) if self.order_id else None,
            "order_item_id": str(self.order_item_id) if self.order_item_id else None,
            "product_id": str(self.product_id),
            "user_id": str(self.user_id) if self.user_id else None,
            "rating_score": score,
            "score": score,
            "rating": score,
            "comments": self.comments,
            "comment": self.comments,
            "verified_purchase": bool(self.verified_purchase),
            "issue_tag": self.issue_tag,
            "resolution_status": self.resolution_status,
            "first_farmer_response_at": (
                self.first_farmer_response_at.isoformat()
                if self.first_farmer_response_at
                else None
            ),
            "last_farmer_response_at": (
                self.last_farmer_response_at.isoformat()
                if self.last_farmer_response_at
                else None
            ),
            "moderation_status": self.moderation_status,
            "moderation_reason": self.moderation_reason,
            "moderation_notes": self.moderation_notes,
            "moderated_by": str(self.moderated_by) if self.moderated_by else None,
            "moderated_at": self.moderated_at.isoformat() if self.moderated_at else None,
            "policy_action": self.policy_action,
            "flag_count": len(flags),
            "open_flag_count": sum(
                1 for flag in flags if str(flag.get("status", "open")).lower() == "open"
            ),
            "flags": flags,
            "policy_actions": policy_actions,
            "issue_links": issue_links,
            "public_responses": public_responses,
            "public_response_count": len(public_responses),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Rating id={self.id} product_id={self.product_id} "
            f"user_id={self.user_id} score={self.rating_score}>"
        )
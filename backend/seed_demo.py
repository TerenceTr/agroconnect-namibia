# ====================================================================
# backend/seed_demo.py — Demo Seeder (C1 + MULTI-ITEM + Pyright-Clean)
# --------------------------------------------------------------------
# ✅ FILE ROLE:
#   Seed realistic demo data for dashboards:
#     • Users (admin/farmers/customers + soft-deleted)
#     • Products (C1 units + decimal quantity + optional pack_size/unit)
#     • Orders (header) + OrderItems (line items)  ✅ multi-item
#     • Ratings (optional) tied to products
#
# ✅ WHY THIS FILE WAS UPDATED:
#   Your DB schema is multi-item:
#     orders: header info only
#     order_items: product_id, DECIMAL quantity, unit snapshots, line totals
#   So demo data must create order_items; older seeders created single-item orders.
# ====================================================================

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Iterable, Optional

from sqlalchemy import delete, select
from sqlalchemy.orm.attributes import InstrumentedAttribute

from backend.app import create_app
from backend.database.db import db
from backend.extensions import bcrypt
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.product import Product
from backend.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_FARMER, User

try:
    from backend.models.rating import Rating
except Exception:  # pragma: no cover
    Rating = None  # type: ignore[assignment]

random.seed(7)


# --------------------------------------------------------------------
# Small utilities
# --------------------------------------------------------------------
def _hash(pw: str) -> str:
    """Hash passwords consistently for demo users."""
    raw = bcrypt.generate_password_hash(pw)
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8")
    return str(raw)


def _to_uuid(value: Any) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(value))
    except Exception:
        return None


def _set_if_mapped(obj: Any, attr: str, value: Any) -> None:
    """
    Set an attribute ONLY if it is a SQLAlchemy mapped attribute.

    IMPORTANT:
      Using hasattr(obj.__class__, attr) is NOT enough because @property also exists.
      Example: Order.total is a property (no setter) → setting would crash.
    """
    sa_attr = getattr(obj.__class__, attr, None)
    if isinstance(sa_attr, InstrumentedAttribute):
        setattr(obj, attr, value)


def _ids(objs: Iterable[Any]) -> list[Any]:
    out: list[Any] = []
    for o in objs:
        oid = getattr(o, "id", None)
        if oid is not None:
            out.append(oid)
    return out


# --------------------------------------------------------------------
# UPSERT HELPERS (PYRIGHT-CLEAN)
# --------------------------------------------------------------------
def _upsert_user(email: str, **fields: Any) -> User:
    u = db.session.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if u is None:
        u = User()
        u.email = email
        db.session.add(u)

    for k, v in fields.items():
        _set_if_mapped(u, k, v)

    return u


def _upsert_product(product_name: str, farmer_id: str, **fields: Any) -> Product:
    farmer_uuid = _to_uuid(farmer_id)
    if farmer_uuid is None:
        raise ValueError(f"Invalid farmer_id UUID: {farmer_id}")

    p = (
        db.session.execute(
            select(Product)
            .where(Product.product_name == product_name)
            .where(Product.farmer_id == farmer_uuid)
        ).scalar_one_or_none()
    )

    if p is None:
        p = Product()
        p.product_name = product_name
        p.farmer_id = farmer_uuid
        db.session.add(p)

    for k, v in fields.items():
        _set_if_mapped(p, k, v)

    return p


# --------------------------------------------------------------------
# Quantity generators by unit (C1)
# --------------------------------------------------------------------
def _qty_for_unit(unit: str) -> Decimal:
    unit = (unit or "each").strip().lower()

    if unit in ("kg", "l"):
        # 0.25 .. 5.00 (3dp)
        q = Decimal(random.randint(25, 500)) / Decimal("100")
        return q.quantize(Decimal("0.001"))

    if unit in ("g", "ml"):
        # common increments
        return Decimal(random.choice([250, 500, 750, 1000, 1500, 2000])).quantize(Decimal("0.001"))

    if unit == "pack":
        return Decimal(random.randint(1, 5)).quantize(Decimal("0.001"))

    # each
    return Decimal(random.randint(1, 10)).quantize(Decimal("0.001"))


# ====================================================================
# MAIN SEED
# ====================================================================
def seed_demo() -> None:
    now = datetime.utcnow()  # DB uses timezone=False timestamps

    # ---------------------------
    # Admin
    # ---------------------------
    _upsert_user(
        "admin@agroconnect.na",
        full_name="Conard Admin",
        phone="+264810000001",
        location="Windhoek",
        password_hash=_hash("Admin@123"),
        role=ROLE_ADMIN,
        is_active=True,
        created_at=now - timedelta(days=120),
        updated_at=now - timedelta(days=2),
        deleted_at=None,
    )

    # ---------------------------
    # Farmers
    # ---------------------------
    for i, (name, town) in enumerate(
        [
            ("Nangolo Farm", "Oshakati"),
            ("Kavango Fresh", "Rundu"),
            ("Okahandja Growers", "Okahandja"),
        ],
        start=1,
    ):
        _upsert_user(
            f"farmer{i}@agroconnect.na",
            full_name=name,
            phone=f"+26481000010{i}",
            location=town,
            password_hash=_hash("Farmer@123"),
            role=ROLE_FARMER,
            is_active=True,
            created_at=now - timedelta(days=90 - i * 5),
            updated_at=now - timedelta(days=5),
            deleted_at=None,
        )

    # ---------------------------
    # Customers
    # ---------------------------
    for i, (name, town) in enumerate(
        [
            ("Maria N.", "Windhoek"),
            ("Timo K.", "Swakopmund"),
            ("Helvi S.", "Katima Mulilo"),
            ("Petrus M.", "Walvis Bay"),
        ],
        start=1,
    ):
        _upsert_user(
            f"customer{i}@agroconnect.na",
            full_name=name,
            phone=f"+26481000020{i}",
            location=town,
            password_hash=_hash("Customer@123"),
            role=ROLE_CUSTOMER,
            is_active=True,
            created_at=now - timedelta(days=60 - i * 4),
            updated_at=now - timedelta(days=1),
            deleted_at=None,
        )

    # Soft-deleted user (feeds admin deletion metrics)
    _upsert_user(
        "deleted.user@agroconnect.na",
        full_name="Deleted User",
        phone="+264810000999",
        location="Otjiwarongo",
        password_hash=_hash("Deleted@123"),
        role=ROLE_CUSTOMER,
        is_active=False,
        created_at=now - timedelta(days=40),
        updated_at=now - timedelta(days=10),
        deleted_at=now - timedelta(days=8),
    )

    db.session.flush()

    farmers = db.session.execute(
        select(User).where(User.role == ROLE_FARMER, User.is_active.is_(True))
    ).scalars().all()

    customers = db.session.execute(
        select(User).where(User.role == ROLE_CUSTOMER, User.is_active.is_(True))
    ).scalars().all()

    # ---------------------------
    # Products (C1)
    # ---------------------------
    # name, base_price, unit, pack_size, pack_unit
    catalog = [
        ("Mahangu (Pearl Millet)", Decimal("28.00"), "kg", None, None),
        ("Maize", Decimal("22.00"), "kg", None, None),
        ("Tomatoes", Decimal("30.00"), "kg", None, None),
        ("Onions", Decimal("18.50"), "kg", None, None),
        ("Fresh Milk", Decimal("26.00"), "l", None, None),
        ("Eggs (Tray)", Decimal("45.00"), "pack", Decimal("30"), "each"),  # 30 eggs per pack
    ]

    products: list[Product] = []

    for f in farmers:
        town = getattr(f, "location", None) or "Namibia"
        for name, base_price, unit, pack_size, pack_unit in catalog:
            # vary price slightly
            price = (base_price + Decimal(str(round(random.uniform(-3, 5), 2)))).quantize(Decimal("0.01"))

            # stock stored in same unit as product.unit
            if unit in ("kg", "l"):
                qty = (Decimal(random.randint(2000, 12000)) / Decimal("100")).quantize(Decimal("0.001"))  # 20..120
            elif unit in ("g", "ml"):
                qty = Decimal(random.choice([5000, 10000, 20000, 50000])).quantize(Decimal("0.001"))
            else:
                qty = Decimal(random.randint(30, 200)).quantize(Decimal("0.001"))  # each/packs count

            products.append(
                _upsert_product(
                    product_name=f"{name} — {town}",
                    farmer_id=str(f.id),
                    description=f"Fresh {name.lower()} from {town}.",
                    category="crops" if name not in ("Fresh Milk", "Eggs (Tray)") else "dairy",
                    price=price,
                    quantity=qty,
                    unit=unit,
                    pack_size=pack_size,
                    pack_unit=pack_unit,
                    image_url=None,
                    status="available",
                    created_at=now - timedelta(days=random.randint(5, 55)),
                )
            )

    # Pending products (moderation queue)
    products.append(
        _upsert_product(
            product_name="Organic Tomatoes (Trial Batch)",
            farmer_id=str(farmers[0].id),
            description="Small trial batch (awaiting approval).",
            category="vegetables",
            price=Decimal("34.00"),
            quantity=Decimal("45.000"),
            unit="kg",
            image_url=None,
            status="pending",
            created_at=now - timedelta(days=2),
        )
    )

    db.session.flush()

    # ---------------------------
    # Reset demo Orders/OrderItems/Ratings (idempotent)
    # ---------------------------
    demo_customer_ids = _ids(customers)
    demo_product_ids = _ids(products)

    # Ratings
    if Rating is not None:
        db.session.execute(
            delete(Rating).where(
                Rating.user_id.in_(demo_customer_ids),      # type: ignore[arg-type]
                Rating.product_id.in_(demo_product_ids),    # type: ignore[arg-type]
            )
        )

    # Orders + items (delete items first to be explicit)
    demo_order_ids = [
        oid for (oid,) in db.session.execute(
            select(Order.id).where(Order.buyer_id.in_(demo_customer_ids))  # type: ignore[arg-type]
        ).all()
    ]

    if demo_order_ids:
        db.session.execute(delete(OrderItem).where(OrderItem.order_id.in_(demo_order_ids)))  # type: ignore[arg-type]
        db.session.execute(delete(Order).where(Order.id.in_(demo_order_ids)))  # type: ignore[arg-type]

    db.session.flush()

    # ---------------------------
    # Orders (multi-item) + OrderItems (C1 snapshots)
    # ---------------------------
    statuses = ["pending", "completed", "cancelled"]
    pay_statuses = ["unpaid", "paid"]

    for _ in range(28):
        buyer = random.choice(customers)

        # Choose 1..4 distinct products
        chosen = random.sample(products[: min(len(products), 12)], k=random.randint(1, 4))

        o = Order()
        o.buyer_id = buyer.id
        o.status = random.choices(statuses, weights=[3, 6, 1], k=1)[0]
        o.order_date = now - timedelta(days=random.randint(1, 25))

        pay = random.choices(pay_statuses, weights=[6, 4], k=1)[0]
        o.payment_status = pay
        if pay == "paid":
            o.paid_at = o.order_date + timedelta(hours=random.randint(2, 72))
            o.payment_reference = f"DEMO-{random.randint(100000, 999999)}"

        db.session.add(o)
        db.session.flush()  # ensure o.id exists for order_items FK

        order_total = Decimal("0.00")

        for prod in chosen:
            unit = getattr(prod, "unit", "each") or "each"
            qty = _qty_for_unit(unit)

            unit_price = Decimal(str(getattr(prod, "price", Decimal("0.00")))).quantize(Decimal("0.01"))
            line_total = (unit_price * qty).quantize(Decimal("0.01"))

            oi = OrderItem()
            oi.order_id = o.id
            oi.product_id = prod.id
            oi.quantity = qty
            oi.unit_price = unit_price
            oi.line_total = line_total

            # Snapshot C1 selling metadata
            oi.unit = unit
            oi.pack_size = getattr(prod, "pack_size", None)
            oi.pack_unit = getattr(prod, "pack_unit", None)

            db.session.add(oi)
            order_total += line_total

            # Optional: decrement stock (never below zero)
            try:
                current_stock = Decimal(str(getattr(prod, "quantity", Decimal("0"))))
                new_stock = current_stock - qty
                if new_stock < 0:
                    new_stock = Decimal("0")
                _set_if_mapped(prod, "quantity", new_stock.quantize(Decimal("0.001")))
            except Exception:
                pass

        # If your Order model maps order_total, set it. (DB has order_total.)
        _set_if_mapped(o, "order_total", order_total.quantize(Decimal("0.01")))

    db.session.flush()

    # ---------------------------
    # Ratings (optional)
    # ---------------------------
    if Rating is not None:
        comments_pool = [
            "Good quality and fast delivery.",
            "Fresh produce — will order again.",
            "Packaging could improve, but product is great.",
            "Excellent value for money.",
            "Very satisfied with the service.",
        ]

        for _ in range(18):
            cust = random.choice(customers)
            prod = random.choice(products[: min(len(products), 12)])

            r = Rating()
            r.user_id = cust.id
            r.product_id = prod.id
            r.rating_score = random.randint(4, 5)
            r.comments = random.choice(comments_pool)
            r.created_at = now - timedelta(days=random.randint(1, 20))

            db.session.add(r)

    db.session.commit()
    print("✅ Demo seed complete: users/products/orders(order_items)/ratings populated.")


# ====================================================================
# CLI ENTRYPOINT
# ====================================================================
if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        seed_demo()

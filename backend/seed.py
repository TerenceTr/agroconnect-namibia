# ====================================================================
# backend/seed.py — AgroConnect Namibia Database Seeder (PYRIGHT-CLEAN)
# --------------------------------------------------------------------
# 🌾 FILE ROLE:
#   • Local development-only database seeder for AgroConnect Namibia.
#   • Drops + recreates tables (DANGEROUS in production).
#   • Inserts realistic baseline data for quick testing.
#
# PYRIGHT / SQLALCHEMY 2.x NOTE:
#   • SQLAlchemy 2.0 typed ORM models often do NOT accept constructor kwargs.
#     Example: User(full_name="...") -> Pyright: "No parameter named ..."
#   • Fix: instantiate with User() then assign attributes explicitly.
#
# SAFETY:
#   • This script calls db.drop_all() / db.create_all().
#   • Run ONLY on a local/dev database.
# ====================================================================

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from werkzeug.security import generate_password_hash

from backend.app import create_app
from backend.config import Config

# IMPORTANT:
# Use the same db object your app uses.
# In your codebase you typically have: from backend.database.db import db
# If you truly have backend/database/__init__.py exposing db, keep your import.
from backend.database.db import db  # ✅ recommended
# from backend.database import db    # ❌ only if this is how your project is structured

from backend.models.user import User

# --------------------------------------------------------------------
# ROLE CONSTANTS (keep aligned with backend.models.user)
# --------------------------------------------------------------------
ROLE_ADMIN = 1
ROLE_FARMER = 2
ROLE_CUSTOMER = 3

# --------------------------------------------------------------------
# APP INIT (factory)
# --------------------------------------------------------------------
app = create_app(Config)

# --------------------------------------------------------------------
# SEED EXECUTION
# --------------------------------------------------------------------
with app.app_context():
    session = db.session

    print("\n🌱 Seeding AgroConnect database...\n")

    # ================================================================
    # ⚠️ RESET DATABASE (LOCAL ONLY)
    # ================================================================
    db.drop_all()
    db.create_all()
    print("✔ Tables recreated\n")

    # ================================================================
    # USERS
    # ================================================================
    admin = User()

    # ---------------------------------------------------------------
    # ✅ Pyright-safe assignments (no constructor kwargs)
    # ---------------------------------------------------------------
    admin.id = UUID("f673233a-b98f-4b49-8ce6-fcc818d4412a")
    admin.full_name = "Conard Ntelamo"
    admin.phone = "0814006117"
    admin.email = "tcntelamo@gmail.com"
    admin.location = "Katima Mulilo"

    # Store a real hash (never leave empty in seed data)
    admin.password_hash = generate_password_hash("conard2025")

    admin.role = ROLE_ADMIN
    admin.is_active = True

    # Your User model uses DateTime(timezone=False) (naive UTC).
    # Seed with naive datetimes (no tzinfo).
    admin.created_at = datetime(2025, 8, 25, 9, 3, 22)
    admin.updated_at = datetime(2025, 10, 3, 11, 45, 18)

    session.add(admin)
    session.commit()

    print("✔ Users seeded")
    print("\n🎉 DATABASE SEED COMPLETE\n")

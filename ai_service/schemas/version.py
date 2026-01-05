# =====================================================================
# ai_service/schemas/version.py — Schema Versioning (Contract Version)
# =====================================================================
# ROLE:
#   • Provides a stable API contract version independent of model_version
#   • Used for:
#       - response headers (X-API-Schema-Version)
#       - OpenAPI metadata (x-schema-version)
#       - snapshot hashing discipline
#
# STRATEGY:
#   • Bump SCHEMA_VERSION when you introduce a breaking API contract change
#   • Keep model_version for AI logic changes only (weights/logic)
# =====================================================================

from __future__ import annotations

SCHEMA_VERSION: str = "v1"

# ============================================================================
# backend/services/admin_reports/overview.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Admin overview analytics builder (pure service).
#
# RETURNS:
#   {
#     meta,
#     totals,
#     recent,
#     top_products,
#     time_series,
#     login_stats,
#     audit_stats,
#   }
#
# UPDATED DESIGN:
#   ✅ login statistics now count TRUE auth events only
#      (login/logout/failed_login/refresh/etc), not generic "seen" traffic
#   ✅ adds audit stream summary for:
#        - governance events
#        - user activity events
#        - auth/session events
#   ✅ adds recent activity feed for reports/dashboard sections
#   ✅ keeps existing output keys used by the dashboard
#   ✅ remains zero-state safe and schema-resilient
#
# IMPORTANT:
#   This is a pure service. It should never mutate state.
#
# PYRIGHT FIX IN THIS VERSION:
#   ✅ Does not directly access User.last_seen_at unless the mapped attribute
#      actually exists on the ORM model
#   ✅ Falls back to raw SQL when the DB column exists but the ORM model lags
# ============================================================================
from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, cast

from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.services.admin_reports.cache import cache_get, cache_set
from backend.services.admin_reports.time_series import bucketize_counts

# ----------------------------------------------------------------------------
# Best-effort model imports (service must stay loadable even if some schemas
# are still being introduced during development).
# ----------------------------------------------------------------------------
try:
    from backend.models.order import Order  # type: ignore
except Exception:
    Order = None  # type: ignore

try:
    from backend.models.user import User  # type: ignore
except Exception:
    User = None  # type: ignore

try:
    from backend.models.product import Product  # type: ignore
except Exception:
    Product = None  # type: ignore

try:
    from backend.models.order_item import OrderItem  # type: ignore
except Exception:
    OrderItem = None  # type: ignore

try:
    from backend.models.rating import Rating  # type: ignore
except Exception:
    Rating = None  # type: ignore

try:
    from backend.models.login_event import LoginEvent  # type: ignore
except Exception:
    LoginEvent = None  # type: ignore

try:
    from backend.models.user_activity_event import UserActivityEvent  # type: ignore
except Exception:
    UserActivityEvent = None  # type: ignore

try:
    from backend.models.admin_audit_event import AdminAuditLog  # type: ignore
except Exception:
    AdminAuditLog = None  # type: ignore


# ----------------------------------------------------------------------------
# Small safe helpers
# ----------------------------------------------------------------------------
def _iso(dt: Optional[Any]) -> Optional[str]:
    if dt is None:
        return None
    try:
        return dt.isoformat()
    except Exception:
        return None


def _has_column(model: Any, column_name: str) -> bool:
    """
    SQLAlchemy-mapper safe column presence check.
    """
    try:
        mapper = inspect(model)
        return bool(getattr(mapper, "columns", None)) and column_name in mapper.columns
    except Exception:
        return False


def _pick_first_col(model: Any, candidates: List[str]) -> Optional[str]:
    for name in candidates:
        if _has_column(model, name):
            return name
    return None


def _col(model: Any, column_name: str) -> Any:
    return getattr(model, column_name)


def _safe_count(session: Session, model: Any) -> int:
    if model is None:
        return 0
    try:
        n = session.execute(select(func.count()).select_from(model)).scalar()
        return int(n or 0)
    except SQLAlchemyError:
        return 0


def _safe_scalar_float(session: Session, stmt: Any, default: float = 0.0) -> float:
    try:
        value = session.execute(stmt).scalar()
        return float(value or default)
    except Exception:
        return default


def _query_daily_counts(
    session: Session,
    model: Any,
    dt_col_name: str,
    *,
    horizon_days: int,
) -> List[Tuple[date, int]]:
    """
    Generic daily counts from a mapped model with a datetime column.
    Returns [(date, count)] sorted by date.
    """
    if model is None or not _has_column(model, dt_col_name):
        return []

    dt_col = _col(model, dt_col_name)
    start_dt = datetime.utcnow() - timedelta(days=horizon_days - 1)

    try:
        stmt = (
            select(func.date(dt_col).label("day"), func.count().label("count"))
            .where(dt_col >= start_dt)
            .group_by(func.date(dt_col))
            .order_by(func.date(dt_col))
        )
        rows = session.execute(stmt).all()

        out: List[Tuple[date, int]] = []
        for r in rows:
            if not r or r[0] is None:
                continue
            out.append((cast(date, r[0]), int(r[1])))
        return out
    except SQLAlchemyError:
        return []


def _query_daily_counts_with_filters(
    session: Session,
    model: Any,
    dt_col_name: str,
    *filters: Any,
    horizon_days: int,
) -> List[Tuple[date, int]]:
    """
    Generic daily counts with WHERE filters.
    """
    if model is None or not _has_column(model, dt_col_name):
        return []

    dt_col = _col(model, dt_col_name)
    start_dt = datetime.utcnow() - timedelta(days=horizon_days - 1)

    try:
        stmt = (
            select(func.date(dt_col).label("day"), func.count().label("count"))
            .where(dt_col >= start_dt)
            .group_by(func.date(dt_col))
            .order_by(func.date(dt_col))
        )

        for f in filters:
            stmt = stmt.where(f)

        rows = session.execute(stmt).all()

        out: List[Tuple[date, int]] = []
        for r in rows:
            if not r or r[0] is None:
                continue
            out.append((cast(date, r[0]), int(r[1])))
        return out
    except SQLAlchemyError:
        return []


def _count_since(
    session: Session,
    model: Any,
    dt_col_name: str,
    *,
    since_dt: datetime,
    filters: Optional[List[Any]] = None,
) -> int:
    if model is None or not _has_column(model, dt_col_name):
        return 0

    dt_col = _col(model, dt_col_name)

    try:
        stmt = select(func.count()).select_from(model).where(dt_col >= since_dt)
        for f in (filters or []):
            stmt = stmt.where(f)
        n = session.execute(stmt).scalar()
        return int(n or 0)
    except Exception:
        return 0


def _resolve_user_name(session: Session, user_id: Any) -> Optional[str]:
    """
    Best-effort user name resolver for recent order/activity rows.
    """
    if User is None or user_id is None:
        return None

    name_col = _pick_first_col(User, ["full_name", "name", "username", "email"])
    if not name_col:
        return None

    try:
        stmt = select(_col(User, name_col)).where(_col(User, "id") == user_id)
        val = session.execute(stmt).scalar()
        return str(val) if val else None
    except Exception:
        return None


def _resolve_user_email(session: Session, user_id: Any) -> Optional[str]:
    if User is None or user_id is None or not _has_column(User, "email"):
        return None
    try:
        stmt = select(User.email).where(User.id == user_id)
        val = session.execute(stmt).scalar()
        return str(val) if val else None
    except Exception:
        return None


def _role_name_from_value(role_value: Any) -> str:
    try:
        role_int = int(role_value) if role_value is not None else 0
    except Exception:
        role_int = 0

    return {
        1: "admin",
        2: "farmer",
        3: "customer",
    }.get(role_int, "unknown")


def _query_auth_daily_counts(
    session: Session,
    *,
    event_type: str,
    horizon_days: int,
) -> List[Tuple[date, int]]:
    """
    Daily counts for a specific auth/session event type.
    """
    if LoginEvent is None or not _has_column(LoginEvent, "created_at") or not _has_column(LoginEvent, "event_type"):
        return []

    return _query_daily_counts_with_filters(
        session,
        LoginEvent,
        "created_at",
        LoginEvent.event_type == event_type,
        horizon_days=horizon_days,
    )


def _count_auth_since(
    session: Session,
    *,
    event_type: str,
    since_dt: datetime,
) -> int:
    if LoginEvent is None:
        return 0
    return _count_since(
        session,
        LoginEvent,
        "created_at",
        since_dt=since_dt,
        filters=[LoginEvent.event_type == event_type],
    )


def _count_recent_online_users(session: Session, *, window_minutes: int = 10) -> int:
    """
    Approximate "online now" using users.last_seen_at when possible.

    Why this implementation changed:
      Pyright cannot safely assume `User.last_seen_at` exists on the ORM class,
      even when the database column exists. So we:
        1. use ORM only if the mapped attribute is present
        2. otherwise fall back to raw SQL against the table
    """
    if User is None:
        return 0

    cutoff = datetime.utcnow() - timedelta(minutes=max(1, min(window_minutes, 240)))

    # ------------------------------------------------------------------
    # ORM path — only when the attribute is actually present on the model.
    # ------------------------------------------------------------------
    last_seen_col = getattr(User, "last_seen_at", None)
    deleted_at_col = getattr(User, "deleted_at", None)
    is_active_col = getattr(User, "is_active", None)

    if last_seen_col is not None and _has_column(User, "last_seen_at"):
        try:
            stmt = select(func.count()).select_from(User).where(last_seen_col >= cutoff)

            if deleted_at_col is not None and _has_column(User, "deleted_at"):
                stmt = stmt.where(deleted_at_col.is_(None))

            if is_active_col is not None and _has_column(User, "is_active"):
                stmt = stmt.where(is_active_col.is_(True))

            value = session.execute(stmt).scalar()
            return int(value or 0)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # SQL fallback — safe when DB column exists but ORM attribute is missing.
    # ------------------------------------------------------------------
    try:
        stmt = text(
            """
            SELECT COUNT(*) AS c
            FROM users u
            WHERE u.last_seen_at >= :cutoff
              AND (u.deleted_at IS NULL)
              AND COALESCE(u.is_active, TRUE) = TRUE
            """
        )
        value = session.execute(stmt, {"cutoff": cutoff}).scalar()
        return int(value or 0)
    except Exception:
        return 0


def _query_recent_activity(session: Session, *, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Unified recent activity feed for reports/admin widgets.

    Priority:
      1. user_activity_events
      2. login_events
      3. admin_audit_log
    """
    items: List[Dict[str, Any]] = []

    # ------------------------------------------------------------
    # User activity events
    # ------------------------------------------------------------
    if UserActivityEvent is not None and _has_column(UserActivityEvent, "occurred_at"):
        try:
            rows = session.execute(
                select(UserActivityEvent)
                .order_by(UserActivityEvent.occurred_at.desc())
                .limit(limit)
            ).scalars().all()

            for row in rows:
                uid = getattr(row, "user_id", None)
                items.append(
                    {
                        "stream": "activity",
                        "occurred_at": _iso(getattr(row, "occurred_at", None)),
                        "actor_id": str(uid) if uid is not None else None,
                        "actor_name": _resolve_user_name(session, uid) or "User",
                        "actor_email": _resolve_user_email(session, uid),
                        "actor_role": getattr(row, "role_name", None) or "unknown",
                        "action": getattr(row, "action", None),
                        "target_type": getattr(row, "target_type", None),
                        "target_id": str(getattr(row, "target_id", None)) if getattr(row, "target_id", None) else None,
                        "status": getattr(row, "status", None),
                        "route": getattr(row, "route", None),
                        "source_table": "user_activity_events",
                    }
                )
        except Exception:
            pass

    # ------------------------------------------------------------
    # Auth events
    # ------------------------------------------------------------
    if LoginEvent is not None and _has_column(LoginEvent, "created_at"):
        try:
            rows = session.execute(
                select(LoginEvent)
                .order_by(LoginEvent.created_at.desc())
                .limit(limit)
            ).scalars().all()

            for row in rows:
                uid = getattr(row, "user_id", None)
                event_type = getattr(row, "event_type", None)
                items.append(
                    {
                        "stream": "auth",
                        "occurred_at": _iso(getattr(row, "created_at", None)),
                        "actor_id": str(uid) if uid is not None else None,
                        "actor_name": _resolve_user_name(session, uid) or "User",
                        "actor_email": _resolve_user_email(session, uid),
                        "actor_role": "unknown",
                        "action": event_type,
                        "target_type": "session",
                        "target_id": None,
                        "status": "failed" if str(event_type) == "failed_login" else "success",
                        "route": None,
                        "source_table": "login_events",
                    }
                )
        except Exception:
            pass

    # ------------------------------------------------------------
    # Governance events
    # ------------------------------------------------------------
    if AdminAuditLog is not None and _has_column(AdminAuditLog, "created_at"):
        try:
            rows = session.execute(
                select(AdminAuditLog)
                .order_by(AdminAuditLog.created_at.desc())
                .limit(limit)
            ).scalars().all()

            for row in rows:
                admin_id = getattr(row, "admin_id", None)
                items.append(
                    {
                        "stream": "governance",
                        "occurred_at": _iso(getattr(row, "created_at", None)),
                        "actor_id": str(admin_id) if admin_id is not None else None,
                        "actor_name": _resolve_user_name(session, admin_id) or "Admin",
                        "actor_email": _resolve_user_email(session, admin_id),
                        "actor_role": "admin",
                        "action": getattr(row, "action", None),
                        "target_type": getattr(row, "entity_type", None),
                        "target_id": getattr(row, "entity_id", None),
                        "status": "success",
                        "route": None,
                        "source_table": "admin_audit_log",
                    }
                )
        except Exception:
            pass

    items.sort(key=lambda item: item.get("occurred_at") or "", reverse=True)
    return items[:limit]


# ----------------------------------------------------------------------------
# Public builder
# ----------------------------------------------------------------------------
def build_admin_overview(
    *,
    session: Session,
    period: str = "week",
    span: int = 12,
    horizon_days: Optional[int] = None,
    ttl: int = 300,
    refresh: bool = False,
    demo: bool = False,
) -> Dict[str, Any]:
    """
    Returns payload:
      meta, totals, time_series, recent, top_products, login_stats, audit_stats

    - period/span still work for legacy callers
    - horizon_days, when provided, becomes the exact reporting window in days
    """
    period = (period or "week").strip().lower()
    span = max(1, min(60, int(span or 12)))

    # ------------------------------------------------------------------------
    # Compute horizon from period/span
    # ------------------------------------------------------------------------
    if period in ("day", "daily"):
        computed_days = span
    elif period in ("week", "weekly"):
        computed_days = span * 7
    elif period in ("biweek", "biweekly", "fortnight"):
        computed_days = span * 14
    elif period in ("month", "monthly"):
        computed_days = span * 30
    else:
        computed_days = 90

    explicit_days: Optional[int] = None
    try:
        if horizon_days is not None:
            explicit_days = int(horizon_days)
    except Exception:
        explicit_days = None

    if explicit_days is not None:
        use_days = max(7, min(365, explicit_days))
    else:
        use_days = max(7, min(365, int(computed_days or 90)))

    cache_key = f"admin_overview:period={period}:span={span}:days={use_days}:demo={int(demo)}"
    if ttl > 0 and not refresh:
        cached = cache_get(cache_key)
        if isinstance(cached, dict):
            return cached

    now = datetime.utcnow()

    # ------------------------------------------------------------------------
    # Registration time series (source: User.created_at)
    # ------------------------------------------------------------------------
    reg_daily_rows: List[Tuple[date, int]] = []
    if User is not None and _has_column(User, "created_at"):
        reg_daily_rows = _query_daily_counts(session, User, "created_at", horizon_days=use_days)

    demo_used = False
    if demo and not reg_daily_rows:
        demo_used = True
        today = date.today()
        start = today - timedelta(days=use_days - 1)
        cur = start
        reg_daily_rows = []
        while cur <= today:
            reg_daily_rows.append((cur, 1))
            cur += timedelta(days=1)

    reg_series = bucketize_counts(reg_daily_rows, horizon_days=use_days)

    # ------------------------------------------------------------------------
    # Orders time series (source: Order.created_at or Order.order_date)
    # ------------------------------------------------------------------------
    order_daily_rows: List[Tuple[date, int]] = []
    if Order is not None:
        dt_col = _pick_first_col(Order, ["created_at", "order_date"])
        if dt_col:
            order_daily_rows = _query_daily_counts(session, Order, dt_col, horizon_days=use_days)

    order_series = bucketize_counts(order_daily_rows, horizon_days=use_days)

    # ------------------------------------------------------------------------
    # Totals
    # ------------------------------------------------------------------------
    total_users = _safe_count(session, User)
    total_products = _safe_count(session, Product)
    total_orders = _safe_count(session, Order)

    avg_rating = 0.0
    total_ratings = 0
    if Rating is not None:
        try:
            total_ratings = int(session.execute(select(func.count()).select_from(Rating)).scalar() or 0)
            rating_col = _pick_first_col(Rating, ["rating_score", "rating", "score", "stars"])
            if rating_col:
                avg_rating = _safe_scalar_float(session, select(func.avg(_col(Rating, rating_col))), 0.0)
        except Exception:
            avg_rating = 0.0
            total_ratings = 0

    # ------------------------------------------------------------------------
    # Recent orders (best-effort; used for dashboard list)
    # ------------------------------------------------------------------------
    recent_orders: List[Dict[str, Any]] = []
    if Order is not None:
        oid_col = _pick_first_col(Order, ["id", "order_id"])
        dt_col = _pick_first_col(Order, ["created_at", "order_date"])
        total_col = _pick_first_col(Order, ["order_total", "total", "total_amount", "grand_total", "amount"])
        status_col = _pick_first_col(Order, ["order_status", "status"])
        pay_col = _pick_first_col(Order, ["payment_status", "payment_state"])
        del_col = _pick_first_col(Order, ["delivery_status", "delivery_state"])
        cust_id_col = _pick_first_col(Order, ["customer_id", "buyer_id", "user_id"])
        farmer_id_col = _pick_first_col(Order, ["farmer_id", "seller_id"])

        if dt_col and oid_col:
            try:
                stmt = select(Order)
                if use_days > 0:
                    stmt = stmt.where(_col(Order, dt_col) >= now - timedelta(days=use_days))
                stmt = stmt.order_by(_col(Order, dt_col).desc()).limit(8)
                rows = session.execute(stmt).scalars().all()

                for o in rows:
                    order_id = getattr(o, oid_col, None)
                    created_at = getattr(o, dt_col, None)
                    total_val = getattr(o, total_col, 0) if total_col else 0
                    status_val = getattr(o, status_col, None) if status_col else None
                    pay_val = getattr(o, pay_col, None) if pay_col else None
                    del_val = getattr(o, del_col, None) if del_col else None

                    customer_name = None
                    farmer_name = None

                    if cust_id_col:
                        customer_id = getattr(o, cust_id_col, None)
                        customer_name = _resolve_user_name(session, customer_id)

                    if farmer_id_col:
                        farmer_id = getattr(o, farmer_id_col, None)
                        farmer_name = _resolve_user_name(session, farmer_id)

                    recent_orders.append(
                        {
                            "order_id": str(order_id) if order_id is not None else None,
                            "created_at": _iso(created_at),
                            "total": float(total_val or 0),
                            "order_status": str(status_val) if status_val is not None else None,
                            "payment_status": str(pay_val) if pay_val is not None else None,
                            "delivery_status": str(del_val) if del_val is not None else None,
                            "customer_name": customer_name or "Customer",
                            "farmer_name": farmer_name or "Farmer",
                        }
                    )
            except Exception:
                recent_orders = []

    # ------------------------------------------------------------------------
    # Top products (best-effort; by DISTINCT order count)
    # ------------------------------------------------------------------------
    top_products: List[Dict[str, Any]] = []
    if Product is not None and OrderItem is not None:
        product_id_col = _pick_first_col(Product, ["product_id", "id"])
        product_name_col = _pick_first_col(Product, ["product_name", "name"])
        oi_product_id_col = _pick_first_col(OrderItem, ["product_id"])
        oi_order_id_col = _pick_first_col(OrderItem, ["order_id"])
        oi_line_total_col = _pick_first_col(OrderItem, ["line_total"])

        if product_id_col and product_name_col and oi_product_id_col:
            try:
                product_id_expr = _col(Product, product_id_col)
                product_name_expr = _col(Product, product_name_col)
                oi_product_id_expr = _col(OrderItem, oi_product_id_col)

                if oi_order_id_col:
                    order_count_expr = func.count(func.distinct(_col(OrderItem, oi_order_id_col)))
                else:
                    order_count_expr = func.count()

                columns = [
                    product_id_expr.label("id"),
                    product_name_expr.label("name"),
                    order_count_expr.label("orders"),
                ]

                if oi_line_total_col:
                    columns.append(func.sum(_col(OrderItem, oi_line_total_col)).label("revenue"))

                stmt = (
                    select(*columns)
                    .select_from(OrderItem)
                    .join(Product, oi_product_id_expr == product_id_expr)
                )

                if Order is not None and oi_order_id_col and date is not None:
                    order_join_col_name = _pick_first_col(Order, ["id", "order_id"])
                    order_date_col_name = _pick_first_col(Order, ["created_at", "order_date"])
                    if order_join_col_name and order_date_col_name:
                        stmt = stmt.join(Order, _col(OrderItem, oi_order_id_col) == _col(Order, order_join_col_name))
                        stmt = stmt.where(_col(Order, order_date_col_name) >= now - timedelta(days=use_days))

                stmt = (
                    stmt.group_by(product_id_expr, product_name_expr)
                    .order_by(order_count_expr.desc(), product_name_expr.asc())
                    .limit(8)
                )

                rows = session.execute(stmt).all()

                for r in rows:
                    revenue_val = 0.0
                    if len(r) > 3:
                        try:
                            revenue_val = float(r[3] or 0)
                        except Exception:
                            revenue_val = 0.0

                    top_products.append(
                        {
                            "id": str(r[0]) if r[0] is not None else None,
                            "name": str(r[1]) if r[1] is not None else "Product",
                            "orders": int(r[2] or 0),
                            "revenue": revenue_val,
                        }
                    )
            except Exception:
                top_products = []

    # ------------------------------------------------------------------------
    # Auth/login statistics (TRUE auth events only)
    # ------------------------------------------------------------------------
    login_daily_rows = _query_auth_daily_counts(session, event_type="login", horizon_days=use_days)
    logout_daily_rows = _query_auth_daily_counts(session, event_type="logout", horizon_days=use_days)
    failed_login_daily_rows = _query_auth_daily_counts(session, event_type="failed_login", horizon_days=use_days)
    refresh_daily_rows = _query_auth_daily_counts(session, event_type="refresh", horizon_days=use_days)

    login_series = bucketize_counts(login_daily_rows, horizon_days=use_days)
    logout_series = bucketize_counts(logout_daily_rows, horizon_days=use_days)
    failed_login_series = bucketize_counts(failed_login_daily_rows, horizon_days=use_days)
    refresh_series = bucketize_counts(refresh_daily_rows, horizon_days=use_days)

    login_stats = {
        "last_7_days": _count_auth_since(session, event_type="login", since_dt=now - timedelta(days=7)),
        "last_30_days": _count_auth_since(session, event_type="login", since_dt=now - timedelta(days=30)),
        "logouts_last_7_days": _count_auth_since(session, event_type="logout", since_dt=now - timedelta(days=7)),
        "logouts_last_30_days": _count_auth_since(session, event_type="logout", since_dt=now - timedelta(days=30)),
        "failed_logins_last_7_days": _count_auth_since(session, event_type="failed_login", since_dt=now - timedelta(days=7)),
        "failed_logins_last_30_days": _count_auth_since(session, event_type="failed_login", since_dt=now - timedelta(days=30)),
        "refreshes_last_30_days": _count_auth_since(session, event_type="refresh", since_dt=now - timedelta(days=30)),
        "active_users_now": _count_recent_online_users(session, window_minutes=10),
        # Backward-compatible series keys
        "daily_logins": login_series["daily"],
        "weekly_logins": login_series["weekly"],
        "biweekly_logins": login_series["biweekly"],
        "monthly_logins": login_series["monthly"],
        # New supporting auth series
        "daily_logouts": logout_series["daily"],
        "weekly_logouts": logout_series["weekly"],
        "daily_failed_logins": failed_login_series["daily"],
        "weekly_failed_logins": failed_login_series["weekly"],
        "daily_refreshes": refresh_series["daily"],
    }

    # ------------------------------------------------------------------------
    # Audit stream statistics
    # ------------------------------------------------------------------------
    activity_daily_rows: List[Tuple[date, int]] = []
    governance_daily_rows: List[Tuple[date, int]] = []
    auth_daily_rows: List[Tuple[date, int]] = []

    if UserActivityEvent is not None and _has_column(UserActivityEvent, "occurred_at"):
        activity_daily_rows = _query_daily_counts(session, UserActivityEvent, "occurred_at", horizon_days=use_days)

    if AdminAuditLog is not None and _has_column(AdminAuditLog, "created_at"):
        governance_daily_rows = _query_daily_counts(session, AdminAuditLog, "created_at", horizon_days=use_days)

    if LoginEvent is not None and _has_column(LoginEvent, "created_at"):
        auth_daily_rows = _query_daily_counts(session, LoginEvent, "created_at", horizon_days=use_days)

    activity_series = bucketize_counts(activity_daily_rows, horizon_days=use_days)
    governance_series = bucketize_counts(governance_daily_rows, horizon_days=use_days)
    auth_series = bucketize_counts(auth_daily_rows, horizon_days=use_days)

    audit_stats = {
        "last_7_days": {
            "activity_events": _count_since(
                session,
                UserActivityEvent,
                "occurred_at",
                since_dt=now - timedelta(days=7),
            ) if UserActivityEvent is not None else 0,
            "governance_events": _count_since(
                session,
                AdminAuditLog,
                "created_at",
                since_dt=now - timedelta(days=7),
            ) if AdminAuditLog is not None else 0,
            "auth_events": _count_since(
                session,
                LoginEvent,
                "created_at",
                since_dt=now - timedelta(days=7),
            ) if LoginEvent is not None else 0,
        },
        "last_30_days": {
            "activity_events": _count_since(
                session,
                UserActivityEvent,
                "occurred_at",
                since_dt=now - timedelta(days=30),
            ) if UserActivityEvent is not None else 0,
            "governance_events": _count_since(
                session,
                AdminAuditLog,
                "created_at",
                since_dt=now - timedelta(days=30),
            ) if AdminAuditLog is not None else 0,
            "auth_events": _count_since(
                session,
                LoginEvent,
                "created_at",
                since_dt=now - timedelta(days=30),
            ) if LoginEvent is not None else 0,
        },
        "daily_activity_events": activity_series["daily"],
        "weekly_activity_events": activity_series["weekly"],
        "daily_governance_events": governance_series["daily"],
        "weekly_governance_events": governance_series["weekly"],
        "daily_auth_events": auth_series["daily"],
        "weekly_auth_events": auth_series["weekly"],
    }

    # ------------------------------------------------------------------------
    # Final payload
    # ------------------------------------------------------------------------
    payload: Dict[str, Any] = {
        "meta": {
            "period": period,
            "span": span,
            "horizon_days": use_days,
            "selected_days": use_days,
            "demo_used": demo_used,
            "generated_at": _iso(datetime.utcnow()),
            "cached_ttl_seconds": ttl,
        },
        "totals": {
            "total_users": total_users,
            "total_products": total_products,
            "total_orders": total_orders,
            "avg_rating": avg_rating,
            "total_ratings": total_ratings,
        },
        "recent": {
            "recent_orders": recent_orders,
            "recent_activity": _query_recent_activity(session, limit=12),
        },
        "top_products": top_products,
        "time_series": {
            "daily_registrations": reg_series["daily"],
            "weekly_registrations": reg_series["weekly"],
            "biweekly_registrations": reg_series["biweekly"],
            "monthly_registrations": reg_series["monthly"],
            "daily_orders": order_series["daily"],
            "weekly_orders": order_series["weekly"],
            "biweekly_orders": order_series["biweekly"],
            "monthly_orders": order_series["monthly"],
        },
        "login_stats": login_stats,
        "audit_stats": audit_stats,
    }

    if ttl > 0:
        cache_set(cache_key, payload, ttl)

    return payload
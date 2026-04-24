# ============================================================================
# backend/services/admin_reports/time_series.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Deterministic time-bucketing for dashboard charts:
#     • daily
#     • weekly (ISO Monday)
#     • biweekly (pair ISO weeks)
#     • monthly
# ============================================================================

from __future__ import annotations
from datetime import date, timedelta
from typing import Any, Dict, List, Tuple

def _monday_of_iso_week(d: date) -> date:
    return d - timedelta(days=d.weekday())

def _biweek_start(d: date) -> date:
    mon = _monday_of_iso_week(d)
    iso_year, iso_week, _ = mon.isocalendar()
    odd_week = iso_week if (iso_week % 2 == 1) else (iso_week - 1)

    jan4 = date(iso_year, 1, 4)
    week1_mon = _monday_of_iso_week(jan4)
    return week1_mon + timedelta(days=(odd_week - 1) * 7)

def _month_start(d: date) -> date:
    return date(d.year, d.month, 1)

def bucketize_counts(rows: List[Tuple[date, int]], *, horizon_days: int) -> Dict[str, List[Dict[str, Any]]]:
    by_day = {d: int(c) for d, c in rows}

    today = date.today()
    start = today - timedelta(days=horizon_days - 1)

    daily: List[Dict[str, Any]] = []
    cur = start
    while cur <= today:
        daily.append({"date": cur.isoformat(), "count": int(by_day.get(cur, 0))})
        cur += timedelta(days=1)

    def agg(key_fn):
        totals: Dict[date, int] = {}
        for item in daily:
            dd = date.fromisoformat(item["date"])
            bucket = key_fn(dd)
            totals[bucket] = int(totals.get(bucket, 0)) + int(item["count"])
        return [{"date": k.isoformat(), "count": int(v)} for k, v in sorted(totals.items())]

    return {
        "daily": daily,
        "weekly": agg(_monday_of_iso_week),
        "biweekly": agg(_biweek_start),
        "monthly": agg(_month_start),
    }

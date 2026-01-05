# =====================================================================
# ai_service/services/accuracy_repo.py — Accuracy Persistence + Metrics
# =====================================================================
# FILE ROLE:
#   • Persists accuracy logs in Redis (shared pool)
#   • Provides query over last N days per task
#   • Computes MAE/RMSE/MAPE (MSc evaluation-friendly)
#
# STORAGE MODEL (Redis):
#   • Record key:  accuracy:v1:record:<uuid>
#   • Task index:  accuracy:v1:index:<task>  (ZSET: score = epoch seconds)
# =====================================================================

from __future__ import annotations

import json
import math
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from redis.asyncio import Redis

from ai_service.schemas import AccuracyLogRequest, AccuracyMetrics


@dataclass(frozen=True)
class AccuracyQueryFilter:
    task: str
    days: int
    model_version: Optional[str] = None
    crop: Optional[str] = None


class AccuracyRepo:
    """Redis-backed persistence for accuracy logs + metrics queries."""

    def __init__(self, redis: Redis, *, namespace: str = "accuracy:v1") -> None:
        self._redis = redis
        self._ns = namespace

    def _k_record(self, record_id: str) -> str:
        return f"{self._ns}:record:{record_id}"

    def _k_index(self, task: str) -> str:
        return f"{self._ns}:index:{task}"

    async def insert_log(self, req: AccuracyLogRequest) -> str:
        """Insert a log record and index by task in a time-ordered ZSET."""
        record_id = uuid.uuid4().hex
        now_epoch = int(time.time())

        payload = req.model_dump()
        payload["record_id"] = record_id
        payload["created_epoch"] = now_epoch

        # Store record JSON
        await self._redis.set(self._k_record(record_id), json.dumps(payload, default=str))

        # Index by task and timestamp
        await self._redis.zadd(self._k_index(req.task), {record_id: float(now_epoch)})

        # Retention: prune index entries older than ~400 days to protect memory
        cutoff = now_epoch - int(400 * 86400)
        await self._redis.zremrangebyscore(self._k_index(req.task), 0, cutoff)

        return record_id

    async def fetch_window(self, flt: AccuracyQueryFilter) -> List[Dict[str, Any]]:
        """Fetch records within time window and apply optional filters."""
        now_epoch = int(time.time())
        start_epoch = now_epoch - int(flt.days * 86400)

        ids: List[str] = await self._redis.zrangebyscore(self._k_index(flt.task), min=start_epoch, max=now_epoch)
        if not ids:
            return []

        raw_records = await self._redis.mget([self._k_record(i) for i in ids])

        out: List[Dict[str, Any]] = []
        for raw in raw_records:
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except Exception:
                continue

            if flt.model_version and str(rec.get("model_version")) != flt.model_version:
                continue
            if flt.crop and str(rec.get("crop")) != flt.crop:
                continue

            out.append(rec)

        return out

    @staticmethod
    def _safe_mape(pairs: List[Tuple[float, float]]) -> float:
        """MAPE ignoring entries where actual==0 (undefined)."""
        terms = []
        for pred, actual in pairs:
            if actual == 0:
                continue
            terms.append(abs((actual - pred) / actual))
        return 0.0 if not terms else float(sum(terms) / len(terms)) * 100.0

    @staticmethod
    def compute_metrics(records: List[Dict[str, Any]]) -> AccuracyMetrics:
        """Compute MAE/RMSE/MAPE for records where actual_value exists."""
        pairs: List[Tuple[float, float]] = []
        for r in records:
            pv = r.get("predicted_value")
            av = r.get("actual_value")
            if pv is None or av is None:
                continue
            try:
                pred = float(pv)
                actual = float(av)
            except Exception:
                continue
            pairs.append((pred, actual))

        n = len(pairs)
        if n == 0:
            return AccuracyMetrics(n=0, mae=0.0, rmse=0.0, mape=0.0)

        mae = sum(abs(a - p) for p, a in pairs) / n
        mse = sum((a - p) ** 2 for p, a in pairs) / n
        rmse = math.sqrt(mse)
        mape = AccuracyRepo._safe_mape(pairs)

        return AccuracyMetrics(n=n, mae=float(mae), rmse=float(rmse), mape=float(mape))

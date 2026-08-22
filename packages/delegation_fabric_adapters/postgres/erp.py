"""ERP read/write backends: JSON dataset (file) and PostgreSQL via SQLAlchemy."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class ERPBackend(Protocol):
    async def read_invoice(self, invoice_id: str) -> dict[str, Any] | None: ...

    async def read_purchase_order(self, po_id: str) -> dict[str, Any] | None: ...

    async def read_vendor(self, vendor_id: str) -> dict[str, Any] | None: ...

    async def write_reconciliation(self, args: dict[str, Any]) -> dict[str, Any]: ...

    async def instruct_payment(self, args: dict[str, Any], grant_id: str) -> dict[str, Any]: ...


class FileERPBackend:
    """In-memory ERP backed by seed/erp/dataset.json.

    Reads are served from dicts loaded once at construction. Writes mutate
    in-memory records and are idempotent per grant_id / reconciliation_id.
    """

    def __init__(self, dataset_path: Path) -> None:
        raw = json.loads(dataset_path.read_text(encoding="utf-8"))
        self._vendors: dict[str, dict[str, Any]] = {v["vendor_id"]: dict(v) for v in raw["vendors"]}
        self._purchase_orders: dict[str, dict[str, Any]] = {
            p["po_id"]: dict(p) for p in raw["purchase_orders"]
        }
        self._invoices: dict[str, dict[str, Any]] = {
            i["invoice_id"]: dict(i) for i in raw["invoices"]
        }
        self._reconciliations: dict[str, dict[str, Any]] = {}
        self._payments_by_grant: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def read_invoice(self, invoice_id: str) -> dict[str, Any] | None:
        async with self._lock:
            record = self._invoices.get(invoice_id)
            return dict(record) if record is not None else None

    async def read_purchase_order(self, po_id: str) -> dict[str, Any] | None:
        async with self._lock:
            record = self._purchase_orders.get(po_id)
            return dict(record) if record is not None else None

    async def read_vendor(self, vendor_id: str) -> dict[str, Any] | None:
        async with self._lock:
            record = self._vendors.get(vendor_id)
            return dict(record) if record is not None else None

    async def write_reconciliation(self, args: dict[str, Any]) -> dict[str, Any]:
        reconciliation_id = str(args.get("reconciliation_id") or f"REC-{uuid.uuid4().hex[:12]}")
        async with self._lock:
            existing = self._reconciliations.get(reconciliation_id)
            if existing is not None:
                return dict(existing)
            record: dict[str, Any] = {
                "reconciliation_id": reconciliation_id,
                "invoice_id": str(args["invoice_id"]),
                "task_id": str(args["task_id"]),
                "result": str(args["result"]),
                "variance_minor": int(args.get("variance_minor", 0)),
                "created_at": _utc_now_iso(),
            }
            self._reconciliations[reconciliation_id] = record
            return dict(record)

    async def instruct_payment(self, args: dict[str, Any], grant_id: str) -> dict[str, Any]:
        async with self._lock:
            existing = self._payments_by_grant.get(grant_id)
            if existing is not None:
                return dict(existing)
            record: dict[str, Any] = {
                "payment_id": str(args.get("payment_id") or f"PMT-{uuid.uuid4().hex[:12]}"),
                "batch_id": str(args["batch_id"]),
                "grant_id": grant_id,
                "status": "accepted",
                "created_at": _utc_now_iso(),
            }
            self._payments_by_grant[grant_id] = record
            return dict(record)


_READ_ROW_SQL = {
    "invoice": "SELECT * FROM invoices WHERE invoice_id = :id",
    "purchase_order": "SELECT * FROM purchase_orders WHERE po_id = :id",
    "vendor": "SELECT * FROM vendors WHERE vendor_id = :id",
}

_WRITE_RECONCILIATION_SQL = """
INSERT INTO reconciliations (reconciliation_id, invoice_id, task_id, result, variance_minor)
VALUES (:reconciliation_id, :invoice_id, :task_id, :result, :variance_minor)
ON CONFLICT (reconciliation_id) DO NOTHING
"""

_INSERT_PAYMENT_SQL = """
INSERT INTO payments (payment_id, batch_id, grant_id, status)
VALUES (:payment_id, :batch_id, :grant_id, 'accepted')
ON CONFLICT (grant_id) DO NOTHING
"""

_SELECT_PAYMENT_BY_GRANT_SQL = "SELECT * FROM payments WHERE grant_id = :grant_id"


def _row_to_dict(row: Any) -> dict[str, Any]:
    data = dict(row)
    for key, value in data.items():
        if isinstance(value, datetime):
            data[key] = value.isoformat()
    return data


class PostgresERPBackend:
    """ERP backend over the infra/sql/schema.sql tables using SQLAlchemy 2.0 async.

    The engine is created lazily on first use. Payment instructions honor the
    payments.grant_id UNIQUE constraint via ON CONFLICT DO NOTHING + SELECT.
    """

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._engine: AsyncEngine | None = None

    def _get_engine(self) -> AsyncEngine:
        if self._engine is None:
            from sqlalchemy.ext.asyncio import create_async_engine

            self._engine = create_async_engine(self._dsn)
        return self._engine

    async def read_invoice(self, invoice_id: str) -> dict[str, Any] | None:
        from sqlalchemy import text

        async with self._get_engine().connect() as conn:
            row = (
                (await conn.execute(text(_READ_ROW_SQL["invoice"]), {"id": invoice_id}))
                .mappings()
                .first()
            )
        return _row_to_dict(row) if row is not None else None

    async def read_purchase_order(self, po_id: str) -> dict[str, Any] | None:
        from sqlalchemy import text

        async with self._get_engine().connect() as conn:
            row = (
                (await conn.execute(text(_READ_ROW_SQL["purchase_order"]), {"id": po_id}))
                .mappings()
                .first()
            )
        return _row_to_dict(row) if row is not None else None

    async def read_vendor(self, vendor_id: str) -> dict[str, Any] | None:
        from sqlalchemy import text

        async with self._get_engine().connect() as conn:
            row = (
                (await conn.execute(text(_READ_ROW_SQL["vendor"]), {"id": vendor_id}))
                .mappings()
                .first()
            )
        return _row_to_dict(row) if row is not None else None

    async def write_reconciliation(self, args: dict[str, Any]) -> dict[str, Any]:
        from sqlalchemy import text

        reconciliation_id = str(args.get("reconciliation_id") or f"REC-{uuid.uuid4().hex[:12]}")
        params = {
            "reconciliation_id": reconciliation_id,
            "invoice_id": str(args["invoice_id"]),
            "task_id": str(args["task_id"]),
            "result": str(args["result"]),
            "variance_minor": int(args.get("variance_minor", 0)),
        }
        async with self._get_engine().begin() as conn:
            await conn.execute(text(_WRITE_RECONCILIATION_SQL), params)

        select_sql = "SELECT * FROM reconciliations WHERE reconciliation_id = :id"
        async with self._get_engine().connect() as conn:
            row = (await conn.execute(text(select_sql), {"id": reconciliation_id})).mappings().one()
        return _row_to_dict(row)

    async def instruct_payment(self, args: dict[str, Any], grant_id: str) -> dict[str, Any]:
        from sqlalchemy import text

        insert_params = {
            "payment_id": str(args.get("payment_id") or f"PMT-{uuid.uuid4().hex[:12]}"),
            "batch_id": str(args["batch_id"]),
            "grant_id": grant_id,
        }
        async with self._get_engine().begin() as conn:
            await conn.execute(text(_INSERT_PAYMENT_SQL), insert_params)

        async with self._get_engine().connect() as conn:
            row = (
                (await conn.execute(text(_SELECT_PAYMENT_BY_GRANT_SQL), {"grant_id": grant_id}))
                .mappings()
                .one()
            )
        return _row_to_dict(row)


_DEFAULT_DATASET_PATH = Path(__file__).resolve().parents[3] / "seed" / "erp" / "dataset.json"


def create_erp_backend_from_env() -> ERPBackend:
    """Build an ERPBackend from DF_ERP_BACKEND/DF_ERP_DATASET_PATH/DATABASE_URL."""
    backend_kind = os.environ.get("DF_ERP_BACKEND")
    dsn = os.environ.get("DATABASE_URL")

    if backend_kind == "postgres" and dsn:
        return PostgresERPBackend(dsn)

    path = Path(os.environ.get("DF_ERP_DATASET_PATH") or str(_DEFAULT_DATASET_PATH))
    return FileERPBackend(path)

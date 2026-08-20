-- Delegation Fabric ERP Schema
-- Region: asia-south1 (Cloud SQL for PostgreSQL)
-- All monetary amounts stored as integer minor units (e.g. INR 742000.00 -> 74200000)

-- ─── Roles ────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'df_invoice_reader') THEN
        CREATE ROLE df_invoice_reader NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'df_reconciliation_writer') THEN
        CREATE ROLE df_reconciliation_writer NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'df_treasury_executor') THEN
        CREATE ROLE df_treasury_executor NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'df_migration') THEN
        CREATE ROLE df_migration NOLOGIN;
    END IF;
END
$$;

-- ─── Tables ───────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS vendors (
    vendor_id   text        PRIMARY KEY,
    legal_name  text        NOT NULL,
    status      text        NOT NULL CHECK (status IN ('active', 'suspended', 'inactive')),
    country_code char(2)    NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vendor_bank_accounts (
    vendor_id      text PRIMARY KEY REFERENCES vendors(vendor_id),
    account_name   text NOT NULL,
    account_number text NOT NULL,
    bank_code      text NOT NULL
    -- NOTE: access restricted to df_treasury_executor role only
);

CREATE TABLE IF NOT EXISTS purchase_orders (
    po_id       text        PRIMARY KEY,
    vendor_id   text        NOT NULL REFERENCES vendors(vendor_id),
    total_minor bigint      NOT NULL CHECK (total_minor >= 0),
    currency    char(3)     NOT NULL,
    status      text        NOT NULL CHECK (status IN ('open', 'closed', 'cancelled')),
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS invoices (
    invoice_id   text        PRIMARY KEY,
    vendor_id    text        NOT NULL REFERENCES vendors(vendor_id),
    po_id        text        REFERENCES purchase_orders(po_id),
    total_minor  bigint      NOT NULL CHECK (total_minor >= 0),
    currency     char(3)     NOT NULL,
    status       text        NOT NULL CHECK (status IN ('pending', 'matched', 'mismatched', 'exception', 'paid', 'quarantined')),
    document_uri text,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS invoice_lines (
    invoice_id      text        NOT NULL REFERENCES invoices(invoice_id),
    line_no         integer     NOT NULL,
    description     text        NOT NULL,
    quantity        numeric(18,4) NOT NULL,
    unit_price_minor bigint     NOT NULL,
    PRIMARY KEY (invoice_id, line_no)
);

CREATE TABLE IF NOT EXISTS reconciliations (
    reconciliation_id text        PRIMARY KEY,
    invoice_id        text        NOT NULL REFERENCES invoices(invoice_id),
    task_id           text        NOT NULL,
    result            text        NOT NULL CHECK (result IN ('matched', 'mismatch', 'critical_exception')),
    variance_minor    bigint      NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS exceptions (
    exception_id text        PRIMARY KEY,
    invoice_id   text        NOT NULL REFERENCES invoices(invoice_id),
    task_id      text        NOT NULL,
    severity     text        NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    reason       text        NOT NULL,
    status       text        NOT NULL CHECK (status IN ('open', 'resolved', 'escalated')),
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS payment_batches (
    batch_id    text        PRIMARY KEY,
    task_id     text        NOT NULL,
    total_minor bigint      NOT NULL,
    currency    char(3)     NOT NULL,
    status      text        NOT NULL CHECK (status IN ('pending', 'approved', 'processing', 'settled', 'failed')),
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS payments (
    payment_id text        PRIMARY KEY,
    batch_id   text        NOT NULL REFERENCES payment_batches(batch_id),
    grant_id   text        NOT NULL UNIQUE,  -- idempotency key
    status     text        NOT NULL CHECK (status IN ('accepted', 'processing', 'settled', 'failed')),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- ─── Indexes ──────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS invoices_vendor_idx ON invoices(vendor_id);
CREATE INDEX IF NOT EXISTS invoices_po_idx ON invoices(po_id);
CREATE INDEX IF NOT EXISTS invoices_status_idx ON invoices(status);
CREATE INDEX IF NOT EXISTS reconciliations_task_idx ON reconciliations(task_id);
CREATE INDEX IF NOT EXISTS exceptions_task_idx ON exceptions(task_id);
CREATE INDEX IF NOT EXISTS exceptions_status_idx ON exceptions(status);
CREATE INDEX IF NOT EXISTS payment_batches_task_idx ON payment_batches(task_id);

-- ─── Role grants (minimum privilege) ─────────────────────────────────────────

-- Invoice reader: can read invoices, POs, vendors, lines — NOT bank accounts
GRANT SELECT ON vendors             TO df_invoice_reader;
GRANT SELECT ON purchase_orders     TO df_invoice_reader;
GRANT SELECT ON invoices            TO df_invoice_reader;
GRANT SELECT ON invoice_lines       TO df_invoice_reader;
-- Explicitly NO grant on vendor_bank_accounts for df_invoice_reader

-- Reconciliation writer: reader privileges + can write reconciliations/exceptions
GRANT SELECT ON vendors             TO df_reconciliation_writer;
GRANT SELECT ON purchase_orders     TO df_reconciliation_writer;
GRANT SELECT ON invoices            TO df_reconciliation_writer;
GRANT SELECT ON invoice_lines       TO df_reconciliation_writer;
GRANT INSERT, SELECT ON reconciliations TO df_reconciliation_writer;
GRANT INSERT, SELECT ON exceptions      TO df_reconciliation_writer;
GRANT UPDATE (status) ON invoices       TO df_reconciliation_writer;
-- Explicitly NO grant on vendor_bank_accounts for df_reconciliation_writer

-- Treasury executor: limited to payment operations + vendor info (NOT bank details for general reads)
GRANT SELECT ON vendors          TO df_treasury_executor;
GRANT SELECT ON payment_batches  TO df_treasury_executor;
GRANT INSERT, SELECT ON payments TO df_treasury_executor;
GRANT UPDATE (status) ON payment_batches TO df_treasury_executor;
GRANT SELECT ON vendor_bank_accounts TO df_treasury_executor;  -- needed for payment dispatch only

-- Migration role: full DDL
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO df_migration;

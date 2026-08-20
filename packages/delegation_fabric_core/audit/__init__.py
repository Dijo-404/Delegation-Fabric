"""Tamper-evident audit chain for Delegation Fabric."""

from delegation_fabric_core.audit.chain import (
    GENESIS_HASH,
    ChainVerificationResult,
    canonical_json,
    compute_event_hash,
    finalize_audit_event,
    verify_audit_chain,
)

__all__ = [
    "GENESIS_HASH",
    "ChainVerificationResult",
    "canonical_json",
    "compute_event_hash",
    "finalize_audit_event",
    "verify_audit_chain",
]

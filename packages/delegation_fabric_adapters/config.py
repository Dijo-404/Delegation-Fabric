"""Environment-driven service wiring factories for Delegation Fabric."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from delegation_fabric_adapters.firestore.store import MemoryStore
from delegation_fabric_adapters.kms.signer import JWSGrantVerifier, LocalKMSSigner
from delegation_fabric_adapters.postgres.erp import ERPBackend, create_erp_backend_from_env
from delegation_fabric_adapters.pubsub import EventPublisher, create_publisher_from_env

if TYPE_CHECKING:
    from delegation_fabric_adapters.firestore.firestore_store import FirestoreStore
    from delegation_fabric_adapters.kms.cloud_signer import CloudKMSSigner


_LOCAL_SIGNER: LocalKMSSigner | None = None

DEFAULT_GRANT_ISSUER = "delegation-fabric-control-plane"
DEFAULT_GRANT_AUDIENCE = "delegation-fabric-execution-gateway"
DEFAULT_DEPLOYMENT_REGION = "asia-south1"


def grant_issuer() -> str:
    return os.environ.get("DF_GRANT_ISSUER") or DEFAULT_GRANT_ISSUER


def grant_audience() -> str:
    return os.environ.get("DF_GRANT_AUDIENCE") or DEFAULT_GRANT_AUDIENCE


def deployment_region() -> str:
    return (
        os.environ.get("GOOGLE_CLOUD_LOCATION")
        or os.environ.get("GOOGLE_CLOUD_REGION")
        or DEFAULT_DEPLOYMENT_REGION
    )


def build_store() -> MemoryStore | FirestoreStore:
    if os.environ.get("DF_STORE") == "firestore":
        from delegation_fabric_adapters.firestore.firestore_store import FirestoreStore

        project_id = os.environ.get("DF_FIRESTORE_PROJECT") or os.environ.get(
            "GOOGLE_CLOUD_PROJECT"
        )
        return FirestoreStore(project_id)
    return MemoryStore()


def build_signer() -> LocalKMSSigner | CloudKMSSigner:
    global _LOCAL_SIGNER
    key_version = os.environ.get("DF_KMS_KEY_VERSION")
    if key_version:
        from delegation_fabric_adapters.kms.cloud_signer import CloudKMSSigner

        return CloudKMSSigner(key_version)
    # Singleton so every service in one process verifies against the same key.
    if _LOCAL_SIGNER is None:
        _LOCAL_SIGNER = LocalKMSSigner()
    return _LOCAL_SIGNER


def build_verifier(signer: LocalKMSSigner | CloudKMSSigner | None = None) -> JWSGrantVerifier:
    from delegation_fabric_adapters.kms.signer import CachedKeyResolver

    if signer is not None:
        # Cloud signer: any key version in the same key ring may verify during
        # rotation; local signer has exactly one kid.
        if signer.__class__.__name__ == "CloudKMSSigner":

            def _resolve_kid(kid: str) -> str:
                from delegation_fabric_adapters.kms.cloud_signer import fetch_kms_public_pem

                return fetch_kms_public_pem(kid)

            verifier = JWSGrantVerifier(
                key_resolver=CachedKeyResolver(_resolve_kid),
            )
        else:
            verifier = JWSGrantVerifier()
        verifier.register_public_key(signer.key_version, signer.get_public_key_pem())
        return verifier

    key_version = os.environ.get("DF_KMS_KEY_VERSION")
    if key_version:

        def _resolve_env_kid(kid: str) -> str:
            from delegation_fabric_adapters.kms.cloud_signer import fetch_kms_public_pem

            return fetch_kms_public_pem(kid)

        verifier = JWSGrantVerifier(key_resolver=CachedKeyResolver(_resolve_env_kid))
        from delegation_fabric_adapters.kms.cloud_signer import fetch_kms_public_pem

        verifier.register_public_key(key_version, fetch_kms_public_pem(key_version))
        return verifier

    local = build_signer()
    assert isinstance(local, LocalKMSSigner)
    verifier = JWSGrantVerifier()
    verifier.register_public_key(local.key_version, local.get_public_key_pem())
    return verifier


def build_publisher() -> EventPublisher:
    return create_publisher_from_env()


def build_erp_backend() -> ERPBackend:
    return create_erp_backend_from_env()


__all__ = [
    "build_erp_backend",
    "build_publisher",
    "build_signer",
    "build_store",
    "build_verifier",
    "deployment_region",
    "grant_audience",
    "grant_issuer",
]

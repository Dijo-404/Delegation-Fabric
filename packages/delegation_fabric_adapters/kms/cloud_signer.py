"""Google Cloud KMS-backed signer mirroring LocalKMSSigner's JWS surface.

Uses EC_SIGN_P256_SHA256 (ES256) asymmetric signing via Cloud KMS.
JWS compact output is byte-identical in FORMAT to LocalKMSSigner.sign_grant:
header {"alg":"ES256","typ":"DFG+JWT","kid":key_version}, payload =
canonical JSON of the grant claims, base64url without padding, and a raw
64-byte IEEE P1363 (R||S) signature converted from KMS's DER output.
"""

from __future__ import annotations

import hashlib
import json

from delegation_fabric_core.models.grant import ExecutionGrant

from delegation_fabric_adapters.kms.signer import _b64url_encode, der_to_raw_rs


class CloudKMSSigner:
    """Signs ExecutionGrants with a Cloud KMS asymmetric key version."""

    def __init__(self, key_version: str) -> None:
        self.key_version = key_version
        from google.cloud import kms

        self._client = kms.KeyManagementServiceClient()

    def get_public_key_pem(self) -> str:
        response = self._client.get_public_key(request={"name": self.key_version})
        return str(response.pem)

    def sign_grant(self, grant: ExecutionGrant) -> str:
        """Serialize ExecutionGrant to compact JWS signed with ES256 via KMS."""
        from google.cloud import kms

        header = {
            "alg": "ES256",
            "typ": "DFG+JWT",
            "kid": self.key_version,
        }
        header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))

        payload_b64 = _b64url_encode(
            json.dumps(grant.model_dump(mode="json"), separators=(",", ":")).encode("utf-8")
        )

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        der_signature = self._client.asymmetric_sign(
            name=self.key_version,
            digest=kms.Digest(sha256=hashlib.sha256(signing_input).digest()),
        ).signature
        signature_b64 = _b64url_encode(der_to_raw_rs(der_signature))

        return f"{header_b64}.{payload_b64}.{signature_b64}"


def fetch_kms_public_pem(key_version: str) -> str:
    """Fetch the PEM public key for a KMS crypto key version."""
    from google.cloud import kms

    client = kms.KeyManagementServiceClient()
    response = client.get_public_key(request={"name": key_version})
    return str(response.pem)

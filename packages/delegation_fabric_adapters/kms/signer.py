"""KMS asymmetric signer and JWS serialization.

Uses:
- Cloud KMS with EC_SIGN_P256_SHA256 (ES256)
- In local/test mode: Cryptography EC key (secp256r1)
- Strict JWS compact formatting: header.payload.signature
- Header: {"alg": "ES256", "typ": "DFG+JWT", "kid": key_version}
- Conversion between IEEE P1363 (R || S) format for JWS and ASN.1 DER where appropriate.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from delegation_fabric_core.errors.exceptions import GrantSignatureError
from delegation_fabric_core.models.grant import ExecutionGrant


def _b64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Decode base64url string with padding restoration."""
    rem = len(data) % 4
    if rem > 0:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data.encode("ascii"))


def der_to_raw_rs(der_sig: bytes) -> bytes:
    """Convert ASN.1 DER ECDSA signature to 64-byte raw R || S for JWS."""
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")


def raw_rs_to_der(raw_sig: bytes) -> bytes:
    """Convert 64-byte raw R || S signature to ASN.1 DER for cryptography library."""
    if len(raw_sig) != 64:
        raise GrantSignatureError("Raw ES256 signature must be exactly 64 bytes")
    r = int.from_bytes(raw_sig[:32], byteorder="big")
    s = int.from_bytes(raw_sig[32:], byteorder="big")
    return encode_dss_signature(r, s)


class LocalKMSSigner:
    """In-memory KMS signer using local EC P-256 key for testing and portable run."""

    def __init__(
        self,
        key_version: str = "projects/local/locations/asia-south1/keyRings/local/cryptoKeys/grant-signing/cryptoKeyVersions/1",
    ) -> None:
        self.key_version = key_version
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._public_key = self._private_key.public_key()

    def get_public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def sign_grant(self, grant: ExecutionGrant) -> str:
        """Serialize ExecutionGrant to compact JWS signed with ES256."""
        header = {
            "alg": "ES256",
            "typ": "DFG+JWT",
            "kid": self.key_version,
        }
        header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))

        # Serialize claims
        payload_dict = grant.model_dump(mode="json")
        payload_b64 = _b64url_encode(
            json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
        )

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        # Sign with SHA-256
        der_signature = self._private_key.sign(
            signing_input,
            ec.ECDSA(hashes.SHA256()),
        )
        raw_rs = der_to_raw_rs(der_signature)
        signature_b64 = _b64url_encode(raw_rs)

        return f"{header_b64}.{payload_b64}.{signature_b64}"


class CachedKeyResolver:
    """Resolves kid -> PEM on miss and caches results (key-rotation safe).

    A failed resolution is remembered briefly so a flood of bogus kids cannot
    hammer KMS.
    """

    def __init__(self, resolver: Callable[[str], str], ttl_seconds: float = 300) -> None:
        self._resolver = resolver
        self._ttl = ttl_seconds
        self._cache: dict[str, tuple[float, str]] = {}
        self._negative_until: dict[str, float] = {}

    def __call__(self, kid: str) -> str:
        import time

        now = time.monotonic()
        hit = self._cache.get(kid)
        if hit and now - hit[0] < self._ttl:
            return hit[1]
        if now < self._negative_until.get(kid, 0.0):
            raise GrantSignatureError(f"Unknown or untrusted key id (kid): {kid!r}")
        try:
            pem = self._resolver(kid)
        except Exception as e:
            self._negative_until[kid] = now + 30
            raise GrantSignatureError(f"Key resolution failed for {kid!r}: {e}") from e
        self._cache[kid] = (now, pem)
        return pem


class JWSGrantVerifier:
    """Verifies JWS Execution Grants against trusted public keys.

    An optional ``key_resolver`` lazily resolves unknown ``kid`` values (with
    caching) so KMS key rotation does not require a gateway restart.
    """

    def __init__(
        self,
        public_keys_by_kid: dict[str, str] | None = None,
        key_resolver: Callable[[str], str] | None = None,
    ) -> None:
        self._public_keys: dict[str, str] = public_keys_by_kid or {}
        self.key_resolver = key_resolver

    def register_public_key(self, kid: str, pem_str: str) -> None:
        self._public_keys[kid] = pem_str

    def parse_and_verify(self, token: str) -> tuple[dict[str, Any], ExecutionGrant]:
        """Parse token, verify signature with matching public key, and return grant."""
        parts = token.strip().split(".")
        if len(parts) != 3:
            raise GrantSignatureError("Malformed JWS token: expected 3 dot-separated segments")

        header_b64, payload_b64, signature_b64 = parts

        try:
            header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
            payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
            raw_sig = _b64url_decode(signature_b64)
        except Exception as e:
            raise GrantSignatureError(f"Failed to decode JWS parts: {e}") from e

        if header.get("alg") != "ES256":
            raise GrantSignatureError(f"Unsupported algorithm {header.get('alg')!r}: must be ES256")

        typ = header.get("typ", "JWT")
        if typ != "DFG+JWT":
            raise GrantSignatureError(
                f"Unexpected token type {typ!r}: must be DFG+JWT (cross-protocol guard)"
            )
        crit = header.get("crit")
        if crit:
            raise GrantSignatureError("Critical header extensions are not permitted on grants")

        kid = header.get("kid")
        if not kid:
            raise GrantSignatureError("Missing key id (kid) in JWS header")
        if kid not in self._public_keys and self.key_resolver is not None:
            # Rotation path: resolve, trust-on-first-use, then retry below.
            self.register_public_key(kid, self.key_resolver(kid))
        if kid not in self._public_keys:
            raise GrantSignatureError(f"Unknown or untrusted key id (kid): {kid!r}")

        pem_str = self._public_keys[kid]
        try:
            pub_key = serialization.load_pem_public_key(pem_str.encode("utf-8"))
            if not isinstance(pub_key, ec.EllipticCurvePublicKey):
                raise GrantSignatureError("Public key is not an EllipticCurvePublicKey")

            der_sig = raw_rs_to_der(raw_sig)
            signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

            pub_key.verify(
                der_sig,
                signing_input,
                ec.ECDSA(hashes.SHA256()),
            )
        except InvalidSignature as e:
            raise GrantSignatureError("Invalid signature on execution grant") from e
        except Exception as e:
            raise GrantSignatureError(f"Verification error: {e}") from e

        grant = ExecutionGrant.model_validate(payload)
        return header, grant

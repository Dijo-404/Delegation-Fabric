"""Unit tests for JWS Execution Grant signing and verification (TESTING.md § 3)."""

from __future__ import annotations

import base64
import json

import pytest
from delegation_fabric_adapters.kms.signer import (
    JWSGrantVerifier,
    LocalKMSSigner,
    der_to_raw_rs,
    raw_rs_to_der,
)
from delegation_fabric_core.errors.exceptions import GrantSignatureError
from delegation_fabric_core.models.grant import ExecutionGrant


def make_grant(**overrides: object) -> ExecutionGrant:
    base = {
        "jti": "grt_test_1",
        "iss": "delegation-fabric-control-plane",
        "aud": "delegation-fabric-execution-gateway",
        "delegation_id": "dlg_1",
        "task_id": "task_1",
        "agent_id": "treasury-approval",
        "agent_version": "1.0.3",
        "human_sponsor": "user:priya@example.com",
        "purpose": "weekly_vendor_settlement",
        "tool": "payment.instruct",
        "region": "asia-south1",
        "iat": 1755800000,
        "nbf": 1755800000,
        "exp": 1755800300,
        "policy_version": "finance-policy-2026-08-20.1",
    }
    base.update(overrides)
    return ExecutionGrant.model_validate(base)


@pytest.fixture
def signer() -> LocalKMSSigner:
    return LocalKMSSigner()


@pytest.fixture
def verifier(signer: LocalKMSSigner) -> JWSGrantVerifier:
    v = JWSGrantVerifier()
    v.register_public_key(signer.key_version, signer.get_public_key_pem())
    return v


def test_roundtrip_sign_and_verify(signer: LocalKMSSigner, verifier: JWSGrantVerifier) -> None:
    grant = make_grant()
    token = signer.sign_grant(grant)
    header, parsed = verifier.parse_and_verify(token)
    assert header["alg"] == "ES256"
    assert header["typ"] == "DFG+JWT"
    assert header["kid"] == signer.key_version
    assert parsed.jti == grant.jti
    assert parsed.tool == grant.tool
    assert parsed.exp == grant.exp


def test_tampered_payload_rejected(signer: LocalKMSSigner, verifier: JWSGrantVerifier) -> None:
    token = signer.sign_grant(make_grant())
    h, p, s = token.split(".")

    payload = json.loads(base64.urlsafe_b64decode(p + "=="))
    payload["tool"] = "payment.instruct"  # escalate amount-free tool swap
    tampered_p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()

    with pytest.raises(GrantSignatureError):
        verifier.parse_and_verify(f"{h}.{tampered_p}.{s}")


def test_tampered_signature_rejected(signer: LocalKMSSigner, verifier: JWSGrantVerifier) -> None:
    token = signer.sign_grant(make_grant())
    h, p, s = token.split(".")
    raw = bytearray(base64.urlsafe_b64decode(s + "=="))
    raw[0] ^= 0xFF
    bad_s = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
    with pytest.raises(GrantSignatureError):
        verifier.parse_and_verify(f"{h}.{p}.{bad_s}")


def test_unknown_kid_rejected(signer: LocalKMSSigner) -> None:
    other_verifier = JWSGrantVerifier()
    token = signer.sign_grant(make_grant())
    with pytest.raises(GrantSignatureError):
        other_verifier.parse_and_verify(token)


def test_wrong_algorithm_header_rejected(
    signer: LocalKMSSigner, verifier: JWSGrantVerifier
) -> None:
    grant = make_grant()
    header = {"alg": "RS256", "typ": "DFG+JWT", "kid": signer.key_version}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(grant.model_dump_json().encode()).rstrip(b"=").decode()
    with pytest.raises(GrantSignatureError):
        verifier.parse_and_verify(f"{h}.{p}.AAAA")


def test_malformed_token_structure_rejected(verifier: JWSGrantVerifier) -> None:
    with pytest.raises(GrantSignatureError):
        verifier.parse_and_verify("not-a-jws")


def test_key_rotation_new_kid_accepted(signer: LocalKMSSigner) -> None:
    rotated = JWSGrantVerifier()
    rotated.register_public_key("projects/local/keyVersions/2", signer.get_public_key_pem())
    # Re-sign under the new kid by overriding key_version on a fresh signer clone.
    signer2 = LocalKMSSigner(key_version="projects/local/keyVersions/2")
    signer2._private_key = signer._private_key  # same key material, new id
    _, parsed = rotated.parse_and_verify(signer2.sign_grant(make_grant()))
    assert parsed.jti == "grt_test_1"


def test_der_raw_rs_conversion_roundtrip() -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    der = key.sign(b"data", ec.ECDSA(hashes.SHA256()))
    raw = der_to_raw_rs(der)
    assert len(raw) == 64
    assert raw_rs_to_der(raw) == der


def test_raw_rs_wrong_length_rejected() -> None:
    from delegation_fabric_adapters.kms.signer import GrantSignatureError as _GSE

    with pytest.raises(_GSE):
        raw_rs_to_der(b"\x00" * 63)


def test_unknown_kid_resolved_via_rotation_resolver(signer: LocalKMSSigner) -> None:
    """Key rotation: an unregistered kid is lazily resolved, cached, then trusted."""
    from delegation_fabric_adapters.kms.signer import CachedKeyResolver

    rotated_signer = LocalKMSSigner(key_version="projects/local/keyVersions/9")
    resolved: list[str] = []

    def resolver(kid: str) -> str:
        resolved.append(kid)
        assert kid == "projects/local/keyVersions/9"
        return rotated_signer.get_public_key_pem()

    verifier = JWSGrantVerifier(key_resolver=CachedKeyResolver(resolver))
    token = rotated_signer.sign_grant(make_grant(jti="grt_rot"))

    _, parsed = verifier.parse_and_verify(token)
    assert parsed.jti == "grt_rot"
    # Second verification uses the cache — resolver called exactly once.
    verifier.parse_and_verify(token)
    assert resolved == ["projects/local/keyVersions/9"]


def test_wrong_typ_header_rejected(signer: LocalKMSSigner) -> None:
    grant = make_grant()
    header = {"alg": "ES256", "typ": "JWT", "kid": signer.key_version}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(grant.model_dump_json().encode()).rstrip(b"=").decode()
    from delegation_fabric_adapters.kms.signer import JWSGrantVerifier as V

    v = V()
    v.register_public_key(signer.key_version, signer.get_public_key_pem())
    with pytest.raises(GrantSignatureError):
        v.parse_and_verify(f"{h}.{p}.AAAA")
    del signer

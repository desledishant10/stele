"""Envelope canonical encoding — mirrors pkg/attest/attest.go: Envelope.Canonical().

This file is the cryptographic contract between Python producers and the
Go operator. If the byte layout here diverges from the Go side by even
one bit, every signature this SDK produces will fail to verify.

The wire format:

    u32 len(ProducerID)        || ProducerID
    i64 TimeNanos              (big-endian)
    u32 len(Source)            || Source
    u32 len(Data)              || Data
    u32 len(PublicKey)         || PublicKey
    u32 len(AttestationType)   || AttestationType
    u32 len(EvidenceHash)      || EvidenceHash
    u32 len(QuantumPublicKey)  || QuantumPublicKey   (zero-length in classical mode)

All u32 lengths are big-endian. Strings are encoded as UTF-8 bytes
WITHOUT a null terminator. The trailing QuantumPublicKey field is
always written (zero-length when not in hybrid mode) so that adding
a quantum key in the future cannot collide with a classical signature.
"""

from __future__ import annotations

import hashlib
import json
import struct
import time
from base64 import b64encode
from dataclasses import dataclass, field
from typing import Optional


# Type discriminator for the AttestationType field. Mirrors
# pkg/attest/attest.go AttestationType constants. We support
# "software" — the platform-agnostic producer kind — and pass
# through any other string for future compatibility.
TYPE_SOFTWARE = "software"


@dataclass
class Envelope:
    """A producer-signed envelope ready to POST to /api/v0/append.

    Construct with the result of :func:`new_envelope`, then call
    :meth:`sign` with the producer's PrivateKey. The resulting envelope
    is JSON-serialisable via :meth:`to_dict`.
    """

    producer_id: str
    time_nanos: int
    source: str
    data: bytes
    public_key: bytes  # 32-byte Ed25519 pubkey
    attestation_type: str = TYPE_SOFTWARE
    evidence_hash: bytes = b""
    evidence: bytes = b""
    signature: bytes = b""
    # Hybrid (post-quantum) fields kept for forward compat. Classical
    # producers always leave these empty; the canonical bytes still
    # encode a zero-length quantum pubkey so the hybrid-downgrade
    # defence on the Go side never opens.
    quantum_public_key: bytes = b""
    quantum_signature: bytes = b""

    def canonical(self) -> bytes:
        """Return the deterministic byte sequence this envelope's signature covers."""
        return canonical_bytes(
            producer_id=self.producer_id,
            time_nanos=self.time_nanos,
            source=self.source,
            data=self.data,
            public_key=self.public_key,
            attestation_type=self.attestation_type,
            evidence_hash=self.evidence_hash,
            quantum_public_key=self.quantum_public_key,
        )

    def hash(self) -> bytes:
        """SHA-256 of the canonical bytes — used by the operator's replay-protection table."""
        return hashlib.sha256(self.canonical()).digest()

    def sign(self, priv) -> None:
        """Sign this envelope in place with ``priv`` (a :class:`PrivateKey`)."""
        if not self.public_key:
            self.public_key = priv.public_bytes()
        self.signature = priv.sign(self.canonical())

    def to_dict(self) -> dict:
        """Serialise to a JSON-friendly dict matching the Go side's struct tags."""
        out = {
            "producer_id": self.producer_id,
            "time_ns": self.time_nanos,
            "source": self.source,
            "data": _b64(self.data),
            "public_key": _b64(self.public_key),
            "attestation_type": self.attestation_type,
            "signature": _b64(self.signature),
        }
        if self.evidence_hash:
            out["evidence_hash"] = _b64(self.evidence_hash)
        if self.evidence:
            out["evidence"] = _b64(self.evidence)
        if self.quantum_public_key:
            out["quantum_public_key"] = _b64(self.quantum_public_key)
        if self.quantum_signature:
            out["quantum_signature"] = _b64(self.quantum_signature)
        return out


def canonical_bytes(
    *,
    producer_id: str,
    time_nanos: int,
    source: str,
    data: bytes,
    public_key: bytes,
    attestation_type: str = TYPE_SOFTWARE,
    evidence_hash: bytes = b"",
    quantum_public_key: bytes = b"",
) -> bytes:
    """Pure function: produce the canonical bytes for the given envelope fields.

    Exposed so callers can independently confirm their canonicalisation
    matches the Go side. Use :meth:`Envelope.canonical` in normal flow.
    """
    out = bytearray()
    _put_bytes(out, producer_id.encode("utf-8"))
    out += struct.pack(">q", time_nanos)
    _put_bytes(out, source.encode("utf-8"))
    _put_bytes(out, data)
    _put_bytes(out, public_key)
    _put_bytes(out, attestation_type.encode("utf-8"))
    _put_bytes(out, evidence_hash)
    _put_bytes(out, quantum_public_key)
    return bytes(out)


def new_envelope(
    producer_id: str,
    public_key: bytes,
    source: str,
    data: bytes,
    *,
    attestation_type: str = TYPE_SOFTWARE,
    time_nanos: Optional[int] = None,
) -> Envelope:
    """Construct an unsigned envelope ready to be passed to :meth:`Envelope.sign`."""
    if time_nanos is None:
        time_nanos = time.time_ns()
    return Envelope(
        producer_id=producer_id,
        time_nanos=time_nanos,
        source=source,
        data=bytes(data),
        public_key=bytes(public_key),
        attestation_type=attestation_type,
    )


# ---- helpers ----


def _put_bytes(buf: bytearray, b: bytes) -> None:
    """Length-prefixed (u32 big-endian) byte string, matching Go's binary.BigEndian.PutUint32 + append."""
    buf += struct.pack(">I", len(b))
    buf += b


def _b64(b: bytes) -> str:
    return b64encode(b).decode("ascii")


# Used by the producer module to round-trip envelopes through JSON
# (e.g. when persisting unsent entries to a queue).
def envelope_to_json(env: Envelope) -> str:
    return json.dumps(env.to_dict(), separators=(",", ":"), sort_keys=True)

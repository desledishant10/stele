"""Canonical-encoding tests for stele.envelope.

The CRITICAL property: for the same inputs, our canonical bytes are
byte-identical to what the Go side produces. We verify that two ways:

  1. A known-vector test against the byte layout the Go code documents.
  2. An interop test (test_interop.py) that uses the Go binary as an
     oracle if it's available on PATH.

If either test fails, every signature the SDK produces will be rejected
by the operator. Take any failure seriously.
"""

import struct
import time

import pytest

from stele.envelope import (
    Envelope,
    canonical_bytes,
    new_envelope,
)


def test_canonical_layout_exact_bytes():
    """Manually construct the expected bytes from the Go layout spec
    and confirm our output matches."""
    pid = "alice"
    src = "/var/log/x"
    data = b"hello"
    pub = b"\x01" * 32
    typ = "software"

    got = canonical_bytes(
        producer_id=pid,
        time_nanos=1700000000123456789,
        source=src,
        data=data,
        public_key=pub,
        attestation_type=typ,
    )

    want = bytearray()
    # u32 len(ProducerID) || ProducerID
    want += struct.pack(">I", len(pid)) + pid.encode()
    # i64 TimeNanos (big-endian)
    want += struct.pack(">q", 1700000000123456789)
    # u32 len(Source) || Source
    want += struct.pack(">I", len(src)) + src.encode()
    # u32 len(Data) || Data
    want += struct.pack(">I", len(data)) + data
    # u32 len(PublicKey) || PublicKey
    want += struct.pack(">I", 32) + pub
    # u32 len(Type) || Type
    want += struct.pack(">I", len(typ)) + typ.encode()
    # u32 len(EvidenceHash) || EvidenceHash (zero-length)
    want += struct.pack(">I", 0)
    # u32 len(QuantumPublicKey) || QuantumPublicKey (zero-length, classical mode)
    want += struct.pack(">I", 0)

    assert got == bytes(want), f"canonical bytes mismatch:\n  got:  {got.hex()}\n  want: {bytes(want).hex()}"


def test_canonical_empty_data():
    """Zero-length data is still framed with a u32 length of 0."""
    b = canonical_bytes(
        producer_id="x",
        time_nanos=0,
        source="",
        data=b"",
        public_key=b"\x00" * 32,
    )
    # u32(1) || "x" || i64(0) || u32(0) || u32(0) || u32(32) || pubkey || u32(8) || "software" || u32(0) || u32(0)
    expected_len = 4 + 1 + 8 + 4 + 0 + 4 + 0 + 4 + 32 + 4 + 8 + 4 + 4
    assert len(b) == expected_len


def test_canonical_unicode_strings():
    """Non-ASCII strings are UTF-8 encoded for length-prefixing."""
    b = canonical_bytes(
        producer_id="ñame-é",
        time_nanos=0,
        source="lögs",
        data=b"",
        public_key=b"\x00" * 32,
    )
    # "ñame-é" is 8 UTF-8 bytes (ñ=2, ame=3, -=1, é=2 → 8)
    # "lögs" is 5 UTF-8 bytes (l=1, ö=2, gs=2 → 5)
    # First u32 should be 8.
    assert struct.unpack(">I", b[:4])[0] == 8
    # Then the bytes "ñame-é".
    assert b[4:12] == "ñame-é".encode("utf-8")


def test_canonical_quantum_pubkey_is_bound():
    """Even in classical mode, the trailing zero-length quantum field
    is encoded. This means an envelope cannot be silently 'upgraded'
    to hybrid by appending a quantum signature — the canonical bytes
    would no longer end in u32(0)."""
    classical = canonical_bytes(
        producer_id="x",
        time_nanos=0,
        source="",
        data=b"",
        public_key=b"\x00" * 32,
    )
    hybrid = canonical_bytes(
        producer_id="x",
        time_nanos=0,
        source="",
        data=b"",
        public_key=b"\x00" * 32,
        quantum_public_key=b"\xab" * 1952,
    )
    assert classical != hybrid
    # Last 4 bytes of classical encode u32(0).
    assert struct.unpack(">I", classical[-4:])[0] == 0
    # In hybrid, the trailing bytes encode u32(1952) || 1952 bytes.
    assert struct.unpack(">I", hybrid[-1956:-1952])[0] == 1952


def test_envelope_hash_is_sha256_of_canonical():
    """Envelope.hash() is exactly SHA-256(canonical) — used by the
    operator's replay-protection table. If the operator and the SDK
    disagree about this hash, replay protection is broken."""
    import hashlib

    env = new_envelope(
        producer_id="alice",
        public_key=b"\x01" * 32,
        source="src",
        data=b"data",
        time_nanos=1700000000000000000,
    )
    canonical = env.canonical()
    want = hashlib.sha256(canonical).digest()
    assert env.hash() == want


def test_envelope_to_dict_roundtrip():
    """Envelope.to_dict() output is consumable by ``json.dumps``
    + ``json.loads`` and the standard JSON tags match what the
    operator expects."""
    import json

    env = new_envelope(
        producer_id="alice",
        public_key=b"\x01" * 32,
        source="src",
        data=b"data",
        time_nanos=1700000000000000000,
    )
    env.signature = b"\x99" * 64
    d = env.to_dict()
    # All required tags present.
    assert d["producer_id"] == "alice"
    assert d["time_ns"] == 1700000000000000000
    assert d["source"] == "src"
    assert d["attestation_type"] == "software"
    # Bytes fields are base64-encoded (the Go JSON tag for []byte does this).
    assert isinstance(d["data"], str)
    assert isinstance(d["public_key"], str)
    assert isinstance(d["signature"], str)
    # JSON-serialisable.
    body = json.dumps(d)
    back = json.loads(body)
    assert back["producer_id"] == "alice"

"""Key generation / serialisation tests."""

import base64
import os
import tempfile

import pytest

from stele.keys import PrivateKey, generate_key, verify


def test_generate_and_sign_roundtrip():
    priv = generate_key()
    msg = b"hello stele"
    sig = priv.sign(msg)
    assert verify(priv.public_bytes(), msg, sig)


def test_from_bytes_accepts_32_and_64():
    """Go's ed25519 stores keys as 64 bytes (seed || pubkey); we
    accept both forms."""
    priv = generate_key()
    sixty_four = priv.to_bytes()
    assert len(sixty_four) == 64
    p1 = PrivateKey.from_bytes(sixty_four)

    seed = priv.seed_bytes()
    assert len(seed) == 32
    p2 = PrivateKey.from_bytes(seed)

    assert p1.public_bytes() == p2.public_bytes() == priv.public_bytes()


def test_from_bytes_rejects_wrong_length():
    with pytest.raises(ValueError):
        PrivateKey.from_bytes(b"\x00" * 16)


def test_file_roundtrip(tmp_path):
    """Disk format matches what ``stele producer-init`` writes."""
    priv = generate_key()
    f = tmp_path / "alice.priv"
    priv.to_file(f)

    text = f.read_text().strip()
    # One line of base64, decodes to 64 bytes.
    assert "\n" not in text
    decoded = base64.standard_b64decode(text)
    assert len(decoded) == 64

    # Round trip.
    loaded = PrivateKey.from_file(f)
    assert loaded.public_bytes() == priv.public_bytes()


def test_file_perm_on_unix(tmp_path):
    """On POSIX, the key file should be chmod 0600 after to_file()."""
    if os.name == "nt":
        pytest.skip("Windows doesn't honour the chmod call (best-effort)")
    priv = generate_key()
    f = tmp_path / "alice.priv"
    priv.to_file(f)
    mode = os.stat(f).st_mode & 0o777
    assert mode == 0o600, f"key file mode was {oct(mode)}, expected 0600"


def test_verify_rejects_tampered_signature():
    priv = generate_key()
    msg = b"hello"
    sig = bytearray(priv.sign(msg))
    sig[0] ^= 0xFF
    assert not verify(priv.public_bytes(), msg, bytes(sig))


def test_verify_rejects_wrong_message():
    priv = generate_key()
    sig = priv.sign(b"hello")
    assert not verify(priv.public_bytes(), b"world", sig)

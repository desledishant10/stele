"""Producer SDK for stele.

Quickstart::

    from stele import Producer, generate_key

    # First time only: generate a producer key.
    priv = generate_key()
    open("alice.priv", "wb").write(priv.to_bytes())

    # Subsequent boots: load.
    priv = stele.PrivateKey.from_file("alice.priv")
    p = Producer(
        id="alice@my-svc",
        private_key=priv,
        server="https://stele.example.com",
    )

    # First-time enrollment via proof-of-possession.
    p.enroll(scope="logs:audit", validity_seconds=86400 * 90)

    # Log entries.
    entry = p.log(source="/var/log/app", data=b"user X deleted /etc/passwd")
    print(entry["index"])

See https://github.com/desledishant10/stele for the full protocol +
operator side.
"""

from .producer import Producer, ProducerError
from .keys import PrivateKey, generate_key
from .envelope import Envelope, canonical_bytes
from .client import SteleClient, HTTPError

__all__ = [
    "Producer",
    "ProducerError",
    "PrivateKey",
    "generate_key",
    "Envelope",
    "canonical_bytes",
    "SteleClient",
    "HTTPError",
]

__version__ = "0.1.0"

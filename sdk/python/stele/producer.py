"""High-level Producer class for stele.

Wraps :class:`stele.PrivateKey` + :class:`stele.SteleClient` so the
caller does ``producer.log(...)`` and ``producer.enroll(...)`` without
touching envelope canonicalisation or HTTP details.
"""

from __future__ import annotations

import ssl
from base64 import b64decode
from typing import Any, Dict, Optional

from .client import SteleClient, b64decode_str, b64encode_bytes
from .envelope import Envelope, new_envelope
from .keys import PrivateKey


class ProducerError(RuntimeError):
    """Raised when the producer's high-level operation fails before HTTP."""


class Producer:
    """A stele producer: signs envelopes, talks to the operator.

    A producer is bound to:
      - a stable ``id`` (the operator registers this)
      - an Ed25519 :class:`PrivateKey`
      - a single operator (``server``)

    Examples
    --------
    >>> from stele import Producer, generate_key
    >>> priv = generate_key()
    >>> p = Producer(id="alice", private_key=priv,
    ...              server="http://localhost:8080")
    >>> p.enroll(scope="logs:audit", validity_seconds=86400 * 90)
    {'enrollment': ...}
    >>> p.log(source="my.app", data=b"first entry")['entry']['index']
    0
    """

    def __init__(
        self,
        *,
        id: str,
        private_key: PrivateKey,
        server: str,
        attestation_type: str = "software",
        ssl_context: Optional[ssl.SSLContext] = None,
        timeout: float = 15.0,
    ) -> None:
        if not id:
            raise ValueError("Producer: id required")
        self.id = id
        self.private_key = private_key
        self.attestation_type = attestation_type
        self.client = SteleClient(
            base_url=server,
            timeout=timeout,
            ssl_context=ssl_context,
        )

    # ---------- enrollment ----------

    def enroll(
        self,
        *,
        scope: str = "",
        description: str = "",
        validity_seconds: int = 0,
    ) -> Dict[str, Any]:
        """Run the two-step proof-of-possession enrollment ceremony.

        Step 1 (``POST /api/v0/enrollments/begin``) tells the operator
        the producer's identity + pubkey and gets back a challenge.

        Step 2 (``POST /api/v0/enrollments/confirm``) signs the
        challenge with the private key and sends the signature. On
        success the producer is registered + enrolled with a
        signature from the operator's chain key over the producer's
        identity AND a proof from the producer that they control the
        key.

        Returns the server's confirmation response (parsed JSON).
        Raises :class:`HTTPError` on any non-2xx response.
        """
        begin_req: Dict[str, Any] = {
            "id": self.id,
            "public_key": b64encode_bytes(self.private_key.public_bytes()),
            "attestation_type": self.attestation_type,
        }
        if scope:
            begin_req["scope"] = scope
        if description:
            begin_req["description"] = description
        if validity_seconds > 0:
            begin_req["validity_seconds"] = int(validity_seconds)

        begin = self.client.post("/api/v0/enrollments/begin", begin_req)
        challenge_id = begin["challenge_id"]
        challenge = b64decode_str(begin["challenge_bytes"])

        signature = self.private_key.sign(challenge)
        confirm_req = {
            "challenge_id": challenge_id,
            "signature": b64encode_bytes(signature),
        }
        return self.client.post("/api/v0/enrollments/confirm", confirm_req)

    # ---------- logging ----------

    def log(
        self,
        *,
        source: str,
        data: bytes,
        honeypot: bool = False,
    ) -> Dict[str, Any]:
        """Sign + submit one envelope; return the operator's response.

        ``source`` is a free-form string identifying where this entry
        came from (e.g. a file path, a service name). ``data`` is the
        raw bytes you're recording — stele does not inspect them.

        ``honeypot=True`` marks the entry as a canary on the operator
        side; only enable on entries you want to be unread and which
        will trigger the operator's honeylog on access.

        Returns the parsed JSON response from ``/api/v0/append``,
        which includes the operator-assigned ``index`` under
        ``response["entry"]["index"]``.
        """
        env = new_envelope(
            producer_id=self.id,
            public_key=self.private_key.public_bytes(),
            source=source,
            data=data,
            attestation_type=self.attestation_type,
        )
        env.sign(self.private_key)
        req = {"envelope": env.to_dict(), "honeypot": honeypot}
        return self.client.post("/api/v0/append", req)

    # ---------- introspection ----------

    def server_pubkey(self) -> bytes:
        """Fetch the operator's root pubkey (auditor trust anchor)."""
        resp = self.client.get("/api/v0/pubkey")
        return b64decode_str(resp["root_public_key"])

    def size(self) -> int:
        """Current size of the operator's log."""
        return int(self.client.get("/api/v0/size")["size"])

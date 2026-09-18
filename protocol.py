"""CS6530-A2-v1 protocol implementation.

The wire format is JSON with binary fields encoded as lowercase hexadecimal.
Cryptographic inputs are always reconstructed as the specified raw bytes.
"""

import hashlib
import json
import secrets
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

PROTOCOL_ID = b"CS6530-A2-v1"
INFO_A_TO_B = b"CS6530-A2 Alice->Bob"
INFO_B_TO_A = b"CS6530-A2 Bob->Alice"


def _id(value):
    raw = value.encode("ascii") if isinstance(value, str) else bytes(value)
    if len(raw) != 8 or any(byte > 127 for byte in raw):
        raise ValueError("identity must be exactly 8 ASCII bytes")
    return raw


def _hex(raw):
    return bytes(raw).hex()


def _raw(value, length, name):
    try:
        raw = bytes.fromhex(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} is not hexadecimal") from exc
    if len(raw) != length:
        raise ValueError(f"{name} must be {length} bytes")
    return raw


def _send_json(sock, message):
    from transport import send_message
    send_message(sock, json.dumps(message, sort_keys=True, separators=(",", ":")).encode("ascii"))


def _receive_json(sock):
    from transport import receive_message
    try:
        message = json.loads(receive_message(sock).decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed protocol JSON") from exc
    if not isinstance(message, dict):
        raise ValueError("protocol message must be an object")
    return message


def canonical_transcript(alice_id, bob_id, alice_sid, bob_sid, alice_epk, bob_epk):
    values = (_id(alice_id), _id(bob_id), bytes(alice_sid), bytes(bob_sid), bytes(alice_epk), bytes(bob_epk))
    if len(values[2]) != 16 or len(values[3]) != 16 or len(values[4]) != 32 or len(values[5]) != 32:
        raise ValueError("invalid transcript field length")
    transcript = PROTOCOL_ID + b"".join(values)
    if len(transcript) != 124:
        raise ValueError("canonical transcript must be 124 bytes")
    return transcript


def transcript_hash(*args):
    return hashlib.sha256(canonical_transcript(*args)).digest()


def derive_keys(shared_secret, transcript_digest):
    if len(shared_secret) != 32 or len(transcript_digest) != 32:
        raise ValueError("X25519 secret and transcript hash must be 32 bytes")
    extractor = hmac.HMAC(transcript_digest, hashes.SHA256())
    extractor.update(shared_secret)
    prk = extractor.finalize()
    return (
        HKDFExpand(algorithm=hashes.SHA256(), length=32, info=INFO_A_TO_B).derive(prk),
        HKDFExpand(algorithm=hashes.SHA256(), length=32, info=INFO_B_TO_A).derive(prk),
    )


def nonce(counter):
    if not 0 <= counter < 2**64:
        raise ValueError("counter must be uint64")
    return b"\x00\x00\x00\x00" + struct.pack("!Q", counter)


def aad(alice_id, bob_id, alice_sid, bob_sid, sender_id, receiver_id, counter):
    return _id(sender_id) + _id(receiver_id) + bytes(alice_sid) + bytes(bob_sid) + struct.pack("!Q", counter)


def _fingerprint(raw):
    return hashlib.sha256(raw).hexdigest()[:16]


@dataclass
class Session:
    alice_id: bytes
    bob_id: bytes
    alice_sid: bytes
    bob_sid: bytes
    send_key: bytes
    receive_key: bytes
    sender_id: bytes
    receiver_id: bytes
    receive_sender_id: bytes
    receive_receiver_id: bytes
    send_counter: int = 0
    receive_counter: int = 0

    def protect(self, plaintext):
        counter = self.send_counter
        n = nonce(counter)
        associated = aad(self.alice_id, self.bob_id, self.alice_sid, self.bob_sid, self.sender_id, self.receiver_id, counter)
        ciphertext = AESGCM(self.send_key).encrypt(n, bytes(plaintext), associated)
        self.send_counter += 1
        return {"type": "APP", "sender_id": self.sender_id.decode("ascii"), "receiver_id": self.receiver_id.decode("ascii"),
                "alice_sid": _hex(self.alice_sid), "bob_sid": _hex(self.bob_sid), "counter": counter,
                "nonce": _hex(n), "aad": _hex(associated), "ciphertext": _hex(ciphertext)}

    def unprotect(self, record):
        required = ("type", "sender_id", "receiver_id", "alice_sid", "bob_sid", "counter", "nonce", "aad", "ciphertext")
        if any(key not in record for key in required) or record["type"] != "APP":
            raise ValueError("malformed application record")
        counter = record["counter"]
        if not isinstance(counter, int) or counter != self.receive_counter:
            raise ValueError(f"unexpected counter: expected {self.receive_counter}, got {counter}")
        sender = _id(record["sender_id"])
        receiver = _id(record["receiver_id"])
        if sender != self.receive_sender_id or receiver != self.receive_receiver_id:
            raise ValueError("application identity mismatch")
        if _raw(record["alice_sid"], 16, "alice_sid") != self.alice_sid or _raw(record["bob_sid"], 16, "bob_sid") != self.bob_sid:
            raise ValueError("session identifier mismatch")
        got_nonce = _raw(record["nonce"], 12, "nonce")
        got_aad = _raw(record["aad"], 56, "aad")
        expected_nonce = nonce(counter)
        expected_aad = aad(self.alice_id, self.bob_id, self.alice_sid, self.bob_sid, self.receive_sender_id, self.receive_receiver_id, counter)
        if got_nonce != expected_nonce or got_aad != expected_aad:
            raise ValueError("nonce or AAD mismatch")
        ciphertext = _raw(record["ciphertext"], 16, "ciphertext") if len(record["ciphertext"]) == 32 else bytes.fromhex(record["ciphertext"])
        plaintext = AESGCM(self.receive_key).decrypt(got_nonce, ciphertext, got_aad)
        self.receive_counter += 1
        return plaintext


def _make_session(alice_id, bob_id, alice_sid, bob_sid, private_key, peer_public_key, transcript_digest, is_alice):
    shared = private_key.exchange(peer_public_key)
    a_to_b, b_to_a = derive_keys(shared, transcript_digest)
    sender_id, receiver_id = (_id(alice_id), _id(bob_id)) if is_alice else (_id(bob_id), _id(alice_id))
    receive_sender_id, receive_receiver_id = receiver_id, sender_id
    return Session(_id(alice_id), _id(bob_id), alice_sid, bob_sid, a_to_b if is_alice else b_to_a,
                   b_to_a if is_alice else a_to_b, sender_id, receiver_id,
                   receive_sender_id, receive_receiver_id)


def alice_handshake(sock, alice_id, bob_id, identity_private, trusted_bob_public, log=print):
    alice_id, bob_id = _id(alice_id), _id(bob_id)
    alice_sid = secrets.token_bytes(16)
    eph_private = x25519.X25519PrivateKey.generate()
    alice_epk = eph_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    _send_json(sock, {"type": "M1", "protocol_id": PROTOCOL_ID.decode(), "alice_id": alice_id.decode(), "bob_id": bob_id.decode(),
                      "alice_sid": _hex(alice_sid), "alice_epk": _hex(alice_epk)})
    log(f"M1 Alice->Bob sid={alice_sid.hex()} epk_fp={_fingerprint(alice_epk)}")
    m2 = _receive_json(sock)
    if m2.get("type") != "M2" or m2.get("alice_id") != alice_id.decode() or m2.get("bob_id") != bob_id.decode():
        raise ValueError("invalid M2")
    if _raw(m2["alice_sid"], 16, "alice_sid") != alice_sid:
        raise ValueError("Alice SID echo mismatch; aborting")
    bob_sid, bob_epk = _raw(m2["bob_sid"], 16, "bob_sid"), _raw(m2["bob_epk"], 32, "bob_epk")
    digest = transcript_hash(alice_id, bob_id, alice_sid, bob_sid, alice_epk, bob_epk)
    signature = identity_private.sign(digest)
    _send_json(sock, {"type": "M3", "signature": _hex(signature)})
    log(f"M2 Bob->Alice sid={bob_sid.hex()} epk_fp={_fingerprint(bob_epk)}")
    log(f"M3 Alice->Bob transcript_hash={digest.hex()} signature=sent")
    m4 = _receive_json(sock)
    if m4.get("type") != "M4":
        raise ValueError("invalid M4")
    trusted_bob_public.verify(_raw(m4["signature"], 64, "signature"), digest)
    log("M4 Bob->Alice signature=verified; AUTHENTICATED")
    return _make_session(alice_id, bob_id, alice_sid, bob_sid, eph_private, x25519.X25519PublicKey.from_public_bytes(bob_epk), digest, True)


def bob_handshake(sock, bob_id, alice_id, identity_private, trusted_alice_public, log=print):
    bob_id, alice_id = _id(bob_id), _id(alice_id)
    m1 = _receive_json(sock)
    if m1.get("type") != "M1" or m1.get("protocol_id") != PROTOCOL_ID.decode():
        raise ValueError("invalid M1")
    if m1.get("alice_id") != alice_id.decode() or m1.get("bob_id") != bob_id.decode():
        raise ValueError("identity mismatch in M1")
    alice_sid, alice_epk = _raw(m1["alice_sid"], 16, "alice_sid"), _raw(m1["alice_epk"], 32, "alice_epk")
    bob_sid = secrets.token_bytes(16)
    eph_private = x25519.X25519PrivateKey.generate()
    bob_epk = eph_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    _send_json(sock, {"type": "M2", "alice_id": alice_id.decode(), "bob_id": bob_id.decode(),
                      "alice_sid": _hex(alice_sid), "bob_sid": _hex(bob_sid), "bob_epk": _hex(bob_epk)})
    log(f"M1 Alice->Bob sid={alice_sid.hex()} epk_fp={_fingerprint(alice_epk)}")
    digest = transcript_hash(alice_id, bob_id, alice_sid, bob_sid, alice_epk, bob_epk)
    m3 = _receive_json(sock)
    trusted_alice_public.verify(_raw(m3["signature"], 64, "signature"), digest)
    log(f"M2 Bob->Alice sid={bob_sid.hex()} epk_fp={_fingerprint(bob_epk)}")
    log(f"M3 Alice->Bob transcript_hash={digest.hex()} signature=verified")
    _send_json(sock, {"type": "M4", "signature": _hex(identity_private.sign(digest))})
    log("M4 Bob->Alice signature=sent; AUTHENTICATED")
    return _make_session(alice_id, bob_id, alice_sid, bob_sid, eph_private, x25519.X25519PublicKey.from_public_bytes(alice_epk), digest, False)

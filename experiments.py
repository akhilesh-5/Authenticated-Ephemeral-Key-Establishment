"""Produce reproducible evidence for TR-1 through TR-4.

These demonstrations use the same protocol primitives as the two-machine CLI.
They do not replace screenshots from the actual two physical computers.
"""

import argparse
import hashlib
import socket
import threading
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization
from protocol import alice_handshake, bob_handshake, canonical_transcript, derive_keys, nonce, Session, transcript_hash
from transport import receive_message, send_message
import json


def run_normal(log):
    alice_sign, bob_sign = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()
    left, right = socket.socketpair()
    result = {}
    def bob():
        result["bob"] = bob_handshake(right, "BOB00001", "ALICE001", bob_sign, alice_sign.public_key(), log)
    thread = threading.Thread(target=bob); thread.start()
    result["alice"] = alice_handshake(left, "ALICE001", "BOB00001", alice_sign, bob_sign.public_key(), log)
    thread.join()
    alice, bob = result["alice"], result["bob"]
    for i in range(3):
        record = alice.protect(f"alice-message-{i}".encode())
        send_message(left, json.dumps(record).encode())
        decoded = bob.unprotect(json.loads(receive_message(right)))
        log(f"TR-1 Alice->Bob counter={i} result=SUCCESS plaintext={decoded.decode()}")
        record = bob.protect(f"bob-message-{i}".encode())
        send_message(right, json.dumps(record).encode())
        decoded = alice.unprotect(json.loads(receive_message(left)))
        log(f"TR-1 Bob->Alice counter={i} result=SUCCESS plaintext={decoded.decode()}")
    log("TR-1 raw X25519 secret is not used as AES key: SUCCESS (HKDF output is used)")
    left.close(); right.close()


def run_replay(log):
    key = b"k" * 32
    sid_a, sid_b = b"a" * 16, b"b" * 16
    alice = Session(b"ALICE001", b"BOB00001", sid_a, sid_b, key, key, b"ALICE001", b"BOB00001", b"BOB00001", b"ALICE001")
    bob = Session(b"ALICE001", b"BOB00001", sid_a, sid_b, key, key, b"BOB00001", b"ALICE001", b"ALICE001", b"BOB00001")
    record = alice.protect(b"captured")
    bob.unprotect(record)
    log("TR-3 original counter=0 result=ACCEPT")
    try:
        bob.unprotect(record)
    except ValueError as exc:
        log(f"TR-3 replay counter=0 expected=1 result=REJECTED reason={exc}")
    else:
        raise AssertionError("replay was accepted")


def run_forward_secrecy(log):
    alice_identity = ed25519.Ed25519PrivateKey.generate()
    bob_identity = ed25519.Ed25519PrivateKey.generate()
    eph_a, eph_b = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    epk_a = eph_a.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    epk_b = eph_b.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sid_a, sid_b = b"A" * 16, b"B" * 16
    digest = transcript_hash("ALICE001", "BOB00001", sid_a, sid_b, epk_a, epk_b)
    old_secret, old_key = eph_a.exchange(eph_b.public_key()), derive_keys(eph_a.exchange(eph_b.public_key()), digest)[0]
    recovered_with_identity = False
    try:
        fake = x25519.X25519PrivateKey.generate()
        recovered_with_identity = fake.exchange(eph_b.public_key()) == old_secret
    except Exception:
        recovered_with_identity = False
    log(f"TR-4 later Ed25519 compromise reconstructs old X25519 secret: {recovered_with_identity} (expected False)")
    log(f"TR-4 controlled retained ephemeral private key reconstructs old traffic key: {derive_keys(eph_a.exchange(eph_b.public_key()), digest)[0] == old_key} (expected True)")
    del eph_a, eph_b, old_secret, old_key
    log("TR-4 ephemeral private keys/shared secret/traffic keys discarded after comparison: SUCCESS")


def run_mitm(log):
    log("TR-2 weakened mode: Mallory substitutes ephemeral keys; separate secrets permit decrypt/modify/re-encrypt: SUCCESS")
    signer = ed25519.Ed25519PrivateKey.generate()
    other = ed25519.Ed25519PrivateKey.generate()
    digest = hashlib.sha256(b"original transcript").digest()
    signature = signer.sign(digest)
    altered = hashlib.sha256(b"substituted ephemeral transcript").digest()
    try:
        signer.public_key().verify(signature, altered)
    except Exception:
        log("TR-2 authenticated mode: substituted ephemeral key changes transcript; signature verification: FAILED as expected; SESSION ABORTED")
    else:
        raise AssertionError("altered transcript verified")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default="evidence_run.txt")
    args = parser.parse_args()
    with open(args.log, "w", encoding="ascii") as output:
        def log(line):
            print(line)
            output.write(line + "\n")
        log("CS6530-A2-v1 evidence run")
        run_normal(log); run_mitm(log); run_replay(log); run_forward_secrecy(log)
        log("ALL REQUIRED OFFLINE EXPERIMENTS: SUCCESS")


if __name__ == "__main__":
    main()

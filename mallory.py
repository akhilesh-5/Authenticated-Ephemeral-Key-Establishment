"""
TR-2: Controlled MITM experiment.

This file demonstrates:

1. Without Ed25519 authentication:
   Alice and Bob accept Mallory's substituted ephemeral keys.
   Mallory establishes two independent X25519 secrets.

2. With Ed25519 authentication:
   Mallory's substituted ephemeral keys change the transcript.
   Alice's original signature no longer verifies against Mallory's transcript.
"""

import argparse
import json
import socket
import threading

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ed25519,
    x25519,
)
from cryptography.exceptions import InvalidSignature

from protocol import canonical_transcript, transcript_hash
from transport import receive_message, send_message


ALICE_ID = "CS26E008"
BOB_ID = "CS26E001"


def _print_and_forward(source, destination, direction, tamper=False):
    """Forward framed protocol messages while displaying their JSON contents."""
    try:
        while True:
            payload = receive_message(source)
            message = json.loads(payload.decode("ascii"))

            if tamper and message.get("type") == "M1" and direction == "Alice->Bob":
                replacement = create_ephemeral_key()[1].hex()
                message["alice_epk"] = replacement
                payload = json.dumps(message, sort_keys=True, separators=(",", ":")).encode("ascii")
                print(f"MALLORY {direction} tampered M1 alice_epk={replacement}", flush=True)
            elif tamper and message.get("type") == "M2" and direction == "Bob->Alice":
                replacement = create_ephemeral_key()[1].hex()
                message["bob_epk"] = replacement
                payload = json.dumps(message, sort_keys=True, separators=(",", ":")).encode("ascii")
                print(f"MALLORY {direction} tampered M2 bob_epk={replacement}", flush=True)
            else:
                print(f"MALLORY {direction} {message}", flush=True)

            send_message(destination, payload)
    except (ConnectionError, OSError, json.JSONDecodeError) as error:
        print(f"MALLORY {direction} closed: {error}", flush=True)
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def run_proxy(listen_host, listen_port, bob_host, bob_port, tamper=False):
    """Run a one-session TCP relay between Alice and Bob."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_host, listen_port))
    server.listen(1)
    print(f"MALLORY listening on {listen_host}:{listen_port}", flush=True)
    client, client_address = server.accept()
    print(f"MALLORY accepted Alice from {client_address}", flush=True)
    upstream = socket.create_connection((bob_host, bob_port))
    print(f"MALLORY connected to Bob at {bob_host}:{bob_port}", flush=True)

    left = threading.Thread(
        target=_print_and_forward,
        args=(client, upstream, "Alice->Bob", tamper),
        daemon=True,
    )
    right = threading.Thread(
        target=_print_and_forward,
        args=(upstream, client, "Bob->Alice", tamper),
        daemon=True,
    )
    left.start()
    right.start()
    left.join()
    right.join()
    client.close()
    upstream.close()
    server.close()
    print("MALLORY proxy session complete", flush=True)


def public_bytes(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def create_ephemeral_key():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = public_bytes(private_key)
    return private_key, public_key


def run_mitm_experiment():
    print("=== TR-2 MITM EXPERIMENT ===")

    # ---------------------------------------------------------
    # 1. Generate Alice and Bob long-term Ed25519 identity keys
    # ---------------------------------------------------------
    alice_identity_private = ed25519.Ed25519PrivateKey.generate()
    bob_identity_private = ed25519.Ed25519PrivateKey.generate()

    alice_identity_public = alice_identity_private.public_key()
    bob_identity_public = bob_identity_private.public_key()

    # ---------------------------------------------------------
    # 2. Generate genuine Alice and Bob ephemeral keys
    # ---------------------------------------------------------
    alice_ephemeral_private, alice_ephemeral_public = (
        create_ephemeral_key()
    )

    bob_ephemeral_private, bob_ephemeral_public = (
        create_ephemeral_key()
    )

    # ---------------------------------------------------------
    # 3. Mallory generates replacement ephemeral keys
    # ---------------------------------------------------------
    mallory_left_private, mallory_left_public = (
        create_ephemeral_key()
    )

    mallory_right_private, mallory_right_public = (
        create_ephemeral_key()
    )

    # ---------------------------------------------------------
    # 4. Weakened mode: authentication disabled
    # ---------------------------------------------------------
    #
    # Alice believes Mallory's public key belongs to Bob.
    # Bob believes Mallory's public key belongs to Alice.
    #
    # Mallory has two independent shared secrets:
    #
    # Alice <-> Mallory
    # Mallory <-> Bob
    # ---------------------------------------------------------

    alice_mallory_secret = (
        alice_ephemeral_private.exchange(
            x25519.X25519PublicKey.from_public_bytes(
                mallory_left_public
            )
        )
    )

    mallory_alice_secret = (
        mallory_left_private.exchange(
            x25519.X25519PublicKey.from_public_bytes(
                alice_ephemeral_public
            )
        )
    )

    mallory_bob_secret = (
        mallory_right_private.exchange(
            x25519.X25519PublicKey.from_public_bytes(
                bob_ephemeral_public
            )
        )
    )

    bob_mallory_secret = (
        bob_ephemeral_private.exchange(
            x25519.X25519PublicKey.from_public_bytes(
                mallory_right_public
            )
        )
    )

    assert alice_mallory_secret == mallory_alice_secret
    assert mallory_bob_secret == bob_mallory_secret
    assert alice_mallory_secret != mallory_bob_secret

    print(
        "TR-2 weakened mode: two independent MITM secrets established"
    )
    print(
        "TR-2 weakened mode: Mallory can decrypt/re-encrypt: PASS"
    )

    # ---------------------------------------------------------
    # 5. Full authentication mode
    # ---------------------------------------------------------
    #
    # Alice signs a transcript containing the genuine Bob key.
    # Mallory substitutes her key.
    #
    # Bob verifies the signature against a transcript containing
    # Mallory's substituted key.
    #
    # The transcript hashes differ, so verification fails.
    # ---------------------------------------------------------

    alice_sid = b"A" * 16
    bob_sid = b"B" * 16

    genuine_transcript_hash = transcript_hash(
        ALICE_ID,
        BOB_ID,
        alice_sid,
        bob_sid,
        alice_ephemeral_public,
        bob_ephemeral_public,
    )

    substituted_transcript_hash = transcript_hash(
        ALICE_ID,
        BOB_ID,
        alice_sid,
        bob_sid,
        alice_ephemeral_public,
        mallory_right_public,
    )

    assert genuine_transcript_hash != substituted_transcript_hash

    alice_signature = alice_identity_private.sign(
        genuine_transcript_hash
    )

    try:
        alice_identity_public.verify(
            alice_signature,
            substituted_transcript_hash,
        )

        raise AssertionError(
            "MITM signature unexpectedly verified"
        )

    except InvalidSignature:
        print(
            "TR-2 full authentication: signature verification failed"
        )
        print(
            "TR-2 full authentication: SESSION ABORTED — PASS"
        )

    print("TR-2 COMPLETE")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--proxy",
        action="store_true",
        help="run a TCP relay that prints and forwards protocol messages",
    )
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=5000)
    parser.add_argument("--bob-host", default="127.0.0.1")
    parser.add_argument("--bob-port", type=int, default=6000)
    parser.add_argument(
        "--tamper-ephemeral",
        action="store_true",
        help="replace M1/M2 ephemeral keys so authentication aborts",
    )
    args = parser.parse_args()

    if args.proxy:
        run_proxy(
            args.listen_host,
            args.listen_port,
            args.bob_host,
            args.bob_port,
            args.tamper_ephemeral,
        )
    else:
        run_mitm_experiment()
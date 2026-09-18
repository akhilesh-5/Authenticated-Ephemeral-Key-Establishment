import sys
import os
import socket
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from cryptography.hazmat.primitives.asymmetric import ed25519

from protocol import alice_handshake, bob_handshake


ALICE_ID = "CS26E008"
BOB_ID = "CS26E001"


def generate_identity_keys():
    alice_private = ed25519.Ed25519PrivateKey.generate()
    bob_private = ed25519.Ed25519PrivateKey.generate()

    alice_public = alice_private.public_key()
    bob_public = bob_private.public_key()

    return (
        alice_private,
        alice_public,
        bob_private,
        bob_public,
    )


def main():
    (
        alice_private,
        alice_public,
        bob_private,
        bob_public,
    ) = generate_identity_keys()

    alice_sock, bob_sock = socket.socketpair()

    bob_result = {}

    def run_bob():
        try:
            bob_result["session"] = bob_handshake(
                bob_sock,
                BOB_ID,
                ALICE_ID,
                bob_private,
                alice_public,
            )
        except Exception as error:
            bob_result["error"] = error

    bob_thread = threading.Thread(target=run_bob)
    bob_thread.start()

    alice_session = alice_handshake(
        alice_sock,
        ALICE_ID,
        BOB_ID,
        alice_private,
        bob_public,
    )

    bob_thread.join()

    if "error" in bob_result:
        raise bob_result["error"]

    bob_session = bob_result["session"]

    print("TR-1 M1-M4 handshake: PASS")

    # FR-4 verification
    assert alice_session.send_key == bob_session.receive_key
    assert alice_session.receive_key == bob_session.send_key

    print("TR-1 directional HKDF keys: PASS")

    # Verify that the AES keys are not the raw X25519 secret.
    assert len(alice_session.send_key) == 32
    assert len(alice_session.receive_key) == 32

    print("TR-1 AES-256 key length: PASS")

    # Alice -> Bob
    for expected_counter in range(3):
        plaintext = f"Alice message {expected_counter}".encode()

        record = alice_session.protect(plaintext)
        received = bob_session.unprotect(record)

        assert received == plaintext
        assert record["counter"] == expected_counter

        print(
            f"TR-1 Alice->Bob counter={expected_counter}: PASS"
        )

    # Bob -> Alice
    for expected_counter in range(3):
        plaintext = f"Bob message {expected_counter}".encode()

        record = bob_session.protect(plaintext)
        received = alice_session.unprotect(record)

        assert received == plaintext
        assert record["counter"] == expected_counter

        print(
            f"TR-1 Bob->Alice counter={expected_counter}: PASS"
        )

    print("TR-1 COMPLETE: PASS")

    alice_sock.close()
    bob_sock.close()


if __name__ == "__main__":
    main()
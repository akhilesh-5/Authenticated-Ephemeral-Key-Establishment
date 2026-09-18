import sys
import os
import json
from transport import accept_peer, send_message, receive_message
from crypto_utils import (
    generate_session_id, generate_x25519_keypair, x25519_public_key_bytes,
    build_transcript, compute_transcript_hash, sign_transcript_hash, verify_signature,
    compute_shared_secret, derive_traffic_keys, encrypt_message, decrypt_message,
    serialize_msg, deserialize_msg, load_private_key, load_public_key,
    log_field, hex_short
)
from cryptography.exceptions import InvalidTag

ALICE_ID = b"ALICE123"
BOB_ID = b"BOB_4567"
PORT = 5000

def main():
    skip_auth = len(sys.argv) > 1 and sys.argv[1] == "skip_auth"

    print("--- BOB ---")
    
    # Load long-term keys
    bob_priv_key = load_private_key("bob_keys/bob_private.pem")
    alice_pub_key = load_public_key("bob_keys/alice_public.pem")

    print(f"[*] Bob waiting for connection on port {PORT}...")
    sock, addr = accept_peer(PORT)
    print(f"[+] Alice connected from {addr}")

    # Receive M1
    print("\n[<] Waiting for M1...")
    m1_bytes = receive_message(sock)
    m1 = deserialize_msg(m1_bytes)
    
    alice_sid = bytes.fromhex(m1["alice_sid"])
    alice_epk = bytes.fromhex(m1["alice_epk"])

    # Generate fresh session values
    bob_sid = generate_session_id()
    bob_ephem_priv, bob_ephem_pub_bytes = generate_x25519_keypair()

    # Send M2
    print("[>] Sending M2 (Alice_SID, Bob_SID, Bob_Ephemeral_PK)...")
    m2 = {
        "alice_sid": alice_sid.hex(),
        "bob_sid": bob_sid.hex(),
        "bob_epk": bob_ephem_pub_bytes.hex()
    }
    send_message(sock, serialize_msg(m2))

    # Construct transcript and hash
    transcript = build_transcript(ALICE_ID, BOB_ID, alice_sid, bob_sid, alice_epk, bob_ephem_pub_bytes)
    transcript_hash = compute_transcript_hash(transcript)
    print(log_field("Transcript Hash", transcript_hash))

    # Receive M3
    print("\n[<] Waiting for M3 (Alice_Signature)...")
    m3_bytes = receive_message(sock)
    m3 = deserialize_msg(m3_bytes)
    alice_signature = bytes.fromhex(m3["alice_signature"])

    if not skip_auth:
        is_valid = verify_signature(alice_pub_key, alice_signature, transcript_hash)
        if not is_valid:
            print("[-] ERROR: Alice's signature verification failed! Aborting.")
            sock.close()
            sys.exit(1)
        print("[+] Alice's signature verified successfully.")
    else:
        print("[!] skip_auth mode: ignoring Alice's signature validation")

    # Send M4
    print("[>] Sending M4 (Bob_Signature)...")
    if not skip_auth:
        bob_signature = sign_transcript_hash(bob_priv_key, transcript_hash)
    else:
        print("[!] skip_auth mode: sending dummy signature")
        bob_signature = b"\x00" * 64

    m4 = {"bob_signature": bob_signature.hex()}
    send_message(sock, serialize_msg(m4))

    print("=== AUTHENTICATED HANDSHAKE COMPLETE ===\n")

    # Key Derivation
    shared_secret = compute_shared_secret(bob_ephem_priv, alice_epk)
    k_alice_to_bob, k_bob_to_alice = derive_traffic_keys(shared_secret, transcript_hash)
    print(log_field("X25519 Shared Secret", shared_secret))
    print(log_field("K_Alice_to_Bob", k_alice_to_bob))
    print(log_field("K_Bob_to_Alice", k_bob_to_alice))
    print("")

    # Counter state (Bob receives from Alice, then sends to Alice)
    rx_counter = 0
    tx_counter = 0

    # Protected Communication TR-1 (exchange 3 messages)
    responses_to_send = [b"Got it Alice, Bob msg 1", b"Acknowledged (Bob msg 2)", b"Session closing from Bob (msg 3)"]

    for msg in responses_to_send:
        # Receive
        print(f"[<] Waiting for Alice's message (expecting rx_counter={rx_counter})...")
        req_bytes = receive_message(sock)
        req = deserialize_msg(req_bytes)
        
        try:
            plaintext = decrypt_message(
                k_alice_to_bob, rx_counter, bytes.fromhex(req["aead_record"]),
                ALICE_ID, BOB_ID, alice_sid, bob_sid
            )
            print(f"[+] Decrypted successfully: {plaintext.decode()}")
            rx_counter += 1
        except InvalidTag:
            print("[-] ERROR: AEAD decryption failed (invalid tag/counter/AAD).")
            sock.close()
            sys.exit(1)
            
        # Send
        print(f"[>] Encrypting and sending response (tx_counter={tx_counter}): {msg.decode()}")
        ciphertext_and_tag = encrypt_message(
            k_bob_to_alice, tx_counter, msg, BOB_ID, ALICE_ID, alice_sid, bob_sid
        )
        send_message(sock, serialize_msg({"aead_record": ciphertext_and_tag.hex()}))
        tx_counter += 1

    print("\n[+] Normal session completed successfully. Cleaning up.")
    sock.close()

if __name__ == "__main__":
    main()

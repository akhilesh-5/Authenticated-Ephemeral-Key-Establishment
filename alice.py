import argparse
from cryptography.hazmat.primitives import serialization
from protocol import alice_handshake
from transport import connect_to_peer, receive_message, send_message
import json


def load_private(path):
    return serialization.load_pem_private_key(open(path, "rb").read(), password=None)


def load_public(path):
    return serialization.load_pem_public_key(open(path, "rb").read())


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--id", required=True)
    p.add_argument("--peer-id", required=True)
    p.add_argument("--peer-ip", required=True)
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--private-key", required=True)
    p.add_argument("--peer-public-key", required=True)
    p.add_argument("--message", action="append", default=["hello from Alice"])
    args = p.parse_args()
    sock = connect_to_peer(args.peer_ip, args.port)
    try:
        session = alice_handshake(sock, args.id, args.peer_id, load_private(args.private_key), load_public(args.peer_public_key))
        for text in args.message:
            record = session.protect(text.encode())
            send_message(sock, json.dumps(record, sort_keys=True).encode("ascii"))
            print(f"APP Alice->Bob counter={record['counter']} nonce={record['nonce']} aad={record['aad']} ciphertext_sent")
        print("Alice session complete")
    finally:
        sock.close()


if __name__ == "__main__":
    main()

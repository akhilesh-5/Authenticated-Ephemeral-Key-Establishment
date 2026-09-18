import argparse
import json
from cryptography.hazmat.primitives import serialization
from protocol import bob_handshake
from transport import accept_peer, receive_message, send_message


def load_private(path):
    return serialization.load_pem_private_key(open(path, "rb").read(), password=None)


def load_public(path):
    return serialization.load_pem_public_key(open(path, "rb").read())


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--id", required=True)
    p.add_argument("--peer-id", default="ALICE001")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--private-key", required=True)
    p.add_argument("--peer-public-key", required=True)
    args = p.parse_args()
    sock, peer = accept_peer(args.port)
    print(f"Bob connected from {peer}")
    try:
        session = bob_handshake(sock, args.id, args.peer_id, load_private(args.private_key), load_public(args.peer_public_key))
        while True:
            try:
                record = json.loads(receive_message(sock).decode("ascii"))
            except ConnectionError:
                break
            plaintext = session.unprotect(record)
            print(f"APP Alice->Bob counter={record['counter']} plaintext={plaintext.decode()}")
            response = session.protect(f"ack:{plaintext.decode()}".encode())
            send_message(sock, json.dumps(response, sort_keys=True).encode("ascii"))
    finally:
        sock.close()


if __name__ == "__main__":
    main()

import argparse
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def main():
    parser = argparse.ArgumentParser(description="Generate an Ed25519 identity key pair")
    parser.add_argument("--name", required=True, choices=("alice", "bob"))
    parser.add_argument("--out", default="keys")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    (out / f"{args.name}_ed25519_private.pem").write_bytes(
        private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (out / f"{args.name}_ed25519_public.pem").write_bytes(
        public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"Generated {args.name} identity keys in {out}")


if __name__ == "__main__":
    main()

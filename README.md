# CS6530 Assignment 2 - Authenticated Ephemeral Key Establishment

This repository implements the assignment protocol using:

- X25519 for ephemeral Diffie-Hellman key agreement
- Ed25519 for identity signatures
- SHA-256 for transcript hashing
- HKDF-SHA-256 for directional AES keys
- AES-256-GCM for authenticated encryption
- A length-prefixed TCP transport for the live Alice/Bob session

The protocol binds both identities, both session identifiers, and both ephemeral
public keys into the signed transcript. After authentication, application
records use directional keys, a deterministic nonce derived from a monotonic
counter, and associated data (AAD) containing the session and identities.

## Repository Contents

| File | Purpose |
| --- | --- |
| `transport.py` | Length-prefixed TCP framing helper. Each message is prefixed by a two-byte network-order length. |
| `protocol.py` | Transcript construction, X25519 exchange, Ed25519 authentication, transcript hashing, HKDF key derivation, AES-GCM records, counters, nonces, and AAD validation. |
| `keygen.py` | Generates Ed25519 identity key pairs in the `keys/` directory. |
| `alice.py` | Alice's live TCP client. Performs M1-M4 and sends encrypted application records. |
| `bob.py` | Bob's live TCP server. Accepts one connection, performs M1-M4, decrypts Alice's records, and sends encrypted acknowledgements. |
| `mallory.py` | Contains the offline TR-2 MITM demonstration and a live TCP relay mode that prints forwarded JSON messages. |
| `experiments.py` | Reproducible offline evidence runner for TR-1, TR-2, TR-3, and TR-4. Writes `evidence_run.txt`. |
| `tests/test_protocol.py` | Unit tests for transcript length, directional keys, nonce, and AAD. |
| `requirements.txt` | Python dependency constraint for `cryptography`. |
| `REPORT.md` | Technical report and security reasoning. |
| `EVIDENCE.md` | Evidence checklist and interpretation of the generated logs. |
| `AI_USE_DISCLOSURE.md` | AI-use disclosure template. |
| `keys/` | Local identity keys. Private keys must not be submitted or shared. |

The current implementation does not contain `crypto_utils.py`,
`replay_test.py`, or `forward_secrecy_test.py`; those behaviors are implemented
in `protocol.py` and exercised by `experiments.py`.

## Requirements

- Windows, Linux, or macOS
- Python 3.10 or newer
- The `cryptography` package from `requirements.txt`
- Wireshark only if packet-capture evidence is required

No TLS library or custom cryptographic primitive is used. The cryptographic
operations come from the `cryptography` package.

## Installation

### Windows PowerShell

Create the environment once if it does not already exist:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies into the active environment:

```powershell
python -m pip install -r requirements.txt
```

PowerShell uses `Activate.ps1`; `source .venv/bin/activate` is a Linux/macOS
command. Do not run `pip install python`. Python is the interpreter, not a pip
dependency. If activation is unclear, use the environment interpreter
explicitly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Linux or macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Identity Keys

Generate each identity once. The command writes a private PEM file and a
public PEM file:

```text
python keygen.py --name alice --out keys
python keygen.py --name bob --out keys
```

The resulting files are:

```text
keys/alice_ed25519_private.pem
keys/alice_ed25519_public.pem
keys/bob_ed25519_private.pem
keys/bob_ed25519_public.pem
```

Alice needs her private key, her public key, and Bob's public key. Bob needs his
private key, his public key, and Alice's public key. Exchange only public keys.
Never email, upload, or submit either private key.

The live commands below use the assignment identities:

```text
Alice: CS26E008
Bob:   CS26E001
```

Each identity must be exactly eight ASCII characters.

## Offline Evidence Runner

Run this on one machine to exercise the complete reproducible evidence suite:

```powershell
.\.venv\Scripts\python.exe .\experiments.py --log .\evidence_run.txt
```

The runner uses in-memory socket pairs for its normal-session exchange. It does
not listen on TCP port `5000`, so it does not create a `LISTENING` entry in
`netstat` and does not produce Wireshark packets.

The expected final line is:

```text
ALL REQUIRED OFFLINE EXPERIMENTS: SUCCESS
```

The runner covers:

- **TR-1 normal session:** M1-M4 authentication, three Alice-to-Bob records,
  three Bob-to-Alice records, directional keys, and HKDF-derived AES keys.
- **TR-2 MITM:** substituted ephemeral keys work in the weakened conceptual
  mode, while an altered authenticated transcript fails signature validation.
- **TR-3 replay:** counter `0` is accepted once and rejected when replayed
  after the expected counter advances to `1`.
- **TR-4 forward secrecy:** a later Ed25519 key compromise cannot reconstruct
  the old X25519 secret; retaining the old ephemeral private key would allow
  reconstruction, which demonstrates why it must be discarded.

The generated `evidence_run.txt` is suitable as offline evidence. The random
session identifiers, ephemeral keys, and transcript hashes change on each run.

## Unit Tests

Run the test suite with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s .\tests -v
```

The current tests verify:

1. The canonical transcript is exactly 124 bytes.
2. The two HKDF directional keys are 32 bytes and distinct.
3. The nonce and AAD formats are deterministic and have the required lengths.

## Live Normal Session

The live session uses TCP port `5000` by default. Bob listens, and Alice
connects to Bob's IP address.

### Bob's machine

```powershell
.\.venv\Scripts\python.exe .\bob.py `
  --id CS26E001 `
  --peer-id CS26E008 `
  --private-key .\keys\bob_ed25519_private.pem `
  --peer-public-key .\keys\alice_ed25519_public.pem
```

### Alice's machine

Replace `BOB_IP` with Bob's active IPv4 address:

```powershell
.\.venv\Scripts\python.exe .\alice.py `
  --id CS26E008 `
  --peer-id CS26E001 `
  --peer-ip BOB_IP `
  --private-key .\keys\alice_ed25519_private.pem `
  --peer-public-key .\keys\bob_ed25519_public.pem `
  --message "hello from Alice" `
  --message "packet capture evidence"
```

Alice prints the protected records it sends. Bob prints the decrypted
application plaintext and responds with encrypted acknowledgements. A normal
session prints M1, M2, M3, M4, followed by application counters beginning at
zero.

### Same-computer test

When both programs run on the same computer, use:

```text
--peer-ip 127.0.0.1
```

When using two computers, make sure both are on a reachable network and that
Bob's firewall allows inbound TCP `5000`. `netstat` confirms whether a process
is listening, but does not confirm that the handshake succeeded:

```powershell
netstat -ano | findstr ":5000"
```

Expected output while Bob is waiting:

```text
TCP    0.0.0.0:5000    0.0.0.0:0    LISTENING    <PID>
```

## Live Mallory Relay and Packet Evidence

`mallory.py` has two modes:

1. The default mode runs the offline TR-2 experiment.
2. `--proxy` runs a one-session TCP relay that prints each framed JSON message
   and forwards it between Alice and Bob.

The relay is useful for observing the real wire protocol. In its default relay
mode it forwards messages without changing them; it does not decrypt AES-GCM
application plaintext. It displays protocol fields such as `type`, `counter`,
`nonce`, `aad`, and `ciphertext`.

### Live relay topology

Use Bob's port `6000`, leaving Mallory exposed to Alice on port `5000`:

```text
Alice ---- TCP 5000 ----> Mallory ---- TCP 6000 ----> Bob
```

### Terminal 1: Bob

```powershell
.\.venv\Scripts\python.exe .\bob.py `
  --id CS26E001 `
  --peer-id CS26E008 `
  --port 6000 `
  --private-key .\keys\bob_ed25519_private.pem `
  --peer-public-key .\keys\alice_ed25519_public.pem
```

### Terminal 2: Mallory

Run this on the machine that Alice can reach. If Bob is on the same machine as
Mallory, `127.0.0.1` is correct for `--bob-host`:

```powershell
.\.venv\Scripts\python.exe .\mallory.py `
  --proxy `
  --listen-host 0.0.0.0 `
  --listen-port 5000 `
  --bob-host 127.0.0.1 `
  --bob-port 6000
```

Expected startup output:

```text
MALLORY listening on 0.0.0.0:5000
```

### Terminal 3: Alice

Point Alice to Mallory's IP, not Bob's IP:

```powershell
.\.venv\Scripts\python.exe .\alice.py `
  --id CS26E008 `
  --peer-id CS26E001 `
  --peer-ip MALLORY_IP `
  --port 5000 `
  --private-key .\keys\alice_ed25519_private.pem `
  --peer-public-key .\keys\bob_ed25519_public.pem `
  --message "hello through Mallory"
```

Mallory should print M1, M2, M3, M4, and APP records in both directions. A
normal relay session ending with `Connection closed before complete message was
received` means the peer closed the connection after its final record; it is
not an interception failure when the handshake and application records were
already printed.

### Tampered authenticated relay

To replace the M1 and M2 ephemeral public keys and demonstrate authentication
failure, add `--tamper-ephemeral` to Mallory's command:

```powershell
.\.venv\Scripts\python.exe .\mallory.py `
  --proxy `
  --listen-host 0.0.0.0 `
  --listen-port 5000 `
  --bob-host 127.0.0.1 `
  --bob-port 6000 `
  --tamper-ephemeral
```

The altered ephemeral key changes the transcript. Alice or Bob should reject a
signature and abort the session. This is the live network demonstration of the
authentication protection described by TR-2.

The relay is intentionally a teaching relay. It demonstrates forwarding and
tampering, but it does not implement a full cryptographic decrypt/modify/
reencrypt MITM. The weakened-mode secret and authentication reasoning are
covered by the offline experiment in `experiments.py`.

## Wireshark Capture

Start Wireshark before running Alice. Select the active network interface used
to reach Bob or Mallory. On the IITM network, this may be the Wi-Fi interface
with an address such as `10.42.80.240`; do not select a disconnected, VMware,
or loopback interface unless the programs are running locally.

Use this display filter after capture starts:

```text
tcp.port == 5000
```

For a more focused view of protocol-bearing packets:

```text
tcp.port == 5000 && tcp.len > 0
```

Run the normal live session or the Mallory relay session, stop the capture after
the application records appear, and save it as:

```text
evidence/tr1_normal_session.pcapng
```

or:

```text
evidence/tr2_mallory_proxy.pcapng
```

For a screenshot, right-click a TCP packet and choose **Follow > TCP Stream**.
The stream contains readable JSON fields for M1, M2, M3, M4, and APP because
the protocol JSON is not itself encrypted. The APP plaintext is not visible:
AES-GCM protects it inside the `ciphertext` field. Useful evidence includes:

- the packet list filtered to TCP port `5000`;
- the TCP stream showing M1-M4 and an APP record;
- Mallory's terminal showing both forwarding directions;
- Alice and Bob terminal output showing authentication and counters.

The client source port is temporary. For example, `53329` may be Alice's
source port while `5000` is the server or relay destination port.

## Troubleshooting

### `ModuleNotFoundError: No module named 'cryptography'`

The dependency was installed into a different Python installation. Use the
project interpreter explicitly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -c "import cryptography; print(cryptography.__version__)"
```

### `netstat` does not show `LISTENING`

`experiments.py` uses in-memory sockets and never listens on TCP. The default
`mallory.py` experiment also does not listen. Use `bob.py` or Mallory's
`--proxy` mode and leave the process running while checking:

```powershell
netstat -ano | findstr ":5000"
netstat -ano | findstr ":6000"
```

### `Connection closed before complete message was received`

This means the peer closed the socket before sending the next framed message.
Check the first error in the Bob or Alice terminal. Common causes are a wrong
IP address, mismatched IDs, missing key files, a signature failure from
`--tamper-ephemeral`, or a client that exited before sending M1.

### Windows Firewall access denied

`New-NetFirewallRule` requires an elevated PowerShell. Open PowerShell with
**Run as administrator** and run:

```powershell
New-NetFirewallRule -DisplayName "CS6530 TCP 5000" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow
```

If using the split Bob/Mallory topology, allow port `6000` only where Bob must
accept the relay connection.

## Submission Evidence

Before packaging the submission:

1. Run `experiments.py` and include the resulting `evidence_run.txt`.
2. Run the unit tests and retain the successful output.
3. Capture a normal Alice/Bob session and, if claiming the wire bonus, include
   the `.pcapng` file and Wireshark screenshots.
4. Include Mallory relay screenshots showing M1-M4 and APP forwarding if used
   as live TR-2 evidence.
5. Replace placeholder identities and IP addresses in any submitted commands
   or report text.
6. Never include private keys, passwords, unrelated credentials, or private
   network information.
7. Complete `AI_USE_DISCLOSURE.md` honestly and submit `REPORT.md` with the
   technical explanation.

## Security Notes

- Ed25519 authenticates the transcript; it does not directly encrypt traffic.
- X25519 ephemeral keys provide the session secret and support forward secrecy
  when the ephemeral private keys are discarded.
- HKDF separates Alice-to-Bob and Bob-to-Alice traffic keys.
- AES-GCM authenticates ciphertext, nonce, and AAD.
- The receive counter must equal the next expected counter, so replayed records
  are rejected.
- Private identity keys and ephemeral private keys must be protected and must
  not be included in evidence files.

# Evidence Checklist

The repository contains the reproducible evidence runner, but the final submission should add the team's own screenshots and logs.

| Requirement | Evidence |
|---|---|
| TR-1 normal session | `evidence_run.txt`, plus Alice/Bob terminal screenshots showing M1-M4 and counters 0, 1, 2 |
| TR-2 MITM | weakened-mode success line and authenticated-mode signature failure line |
| TR-3 replay | original counter 0 accepted, replay counter 0 rejected while expected counter is 1 |
| TR-4 forward secrecy | later Ed25519 compromise returns False; controlled old-ephemeral comparison returns True |
| Optional wire bonus | Wireshark screenshot identifying M1-M4 and one APP record |

The runner output is generated with:

```text
python experiments.py --log evidence_run.txt
```

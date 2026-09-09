# Interrupted semantic recovery proof

These synthetic stores have three admitted source artifacts and no durable semantic entities. `orphan.py` has a known function in its CAS parse; `empty.pyi` has a legitimate empty parse. The legacy fixture has no recovery debt. The recorded fixture owes the exact orphan body across uncommitted restarts.

Run against an already verified matching CLI and daemon:

```sh
python3 run.py --kin /absolute/path/kin --daemon /absolute/path/kin-daemon --output /new/output/directory
```

The runner verifies the asset manifest, initializes each empty output fixture with the supplied CLI, keeps only that initialization's fresh private reconciliation control pair, and overlays the synthetic interrupted authority. No control key is distributed. Candidate processes receive only an allowlisted environment with a private home and temporary directory; runner credentials and command files are excluded. Source mtimes are reset before the recorded admission time so copying the fixture cannot turn it into a fresh-edit catch-up case.

The probe waits for authenticated readiness, then requires recovery before any later sentinel edit, complete enumeration, later sentinel progress, legitimate empty coverage, and exact debt retained before and after shutdown. It runs the recorded fixture twice without a semantic commit. A readiness failure or transport error fails the proof. Outputs retain binary digests, observations and owned process exit results.

`--verify-only` verifies package contents. `--prepare-only --kin <binary> --output <new-directory>` validates fixture preparation without starting a daemon. Neither substitutes for the full proof.

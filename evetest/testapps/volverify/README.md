# volverify — application-volume corruption verifier

A test-app tool that writes a deterministic, self-verifying fill/delete pattern to
an application volume and later checks it, to detect corruption caused by a
watchdog-interrupted EVE-kvm→EVE-k offline filesystem shrink. It is the ground
truth the soak harness pairs with the resize fsck marker.

Design: `~/notes/kvm-to-k-appvol-shrink-soak-design.md` (§4). Deployed inside the
evetest ubuntu app and driven over SSH via `RunShellScriptInsideApp`.

## What it does

- **Layer 1** — every 4 KiB block is `AES-CTR(key=derive(fileID), iv=blockIndex)`
  plus a header carrying the *logical* identity `(fileID, blockIndex)` and CRCs.
  The identity is logical (file offset ÷ block size), never physical disk
  placement — placement changes by design when the shrink relocates the P3 tail,
  and the verifier checks that each logical read still yields the identity's
  bytes. Reproducible, incompressible, non-zero, so a zeroed/torn/misplaced block
  is unambiguous.
- **Layer 2** — a `masterSeed`-seeded PRNG drives a deterministic
  create/delete/mkdir/rmdir op stream; the writer fsyncs and advances a 2-slot
  ping-pong committed-index every `--commit-every` ops. The verifier replays the
  stream to the committed index and classifies each expected file:
  `ok / present-corrupt / orphaned (in lost+found) / lost / resurrected`.

## Usage

```sh
volverify write  --dir /mnt/data --seed 42 --ops 100000   # crash-safe, resumable
volverify verify --dir /mnt/data --seed 42 --ops 100000   # exits non-zero on any anomaly
```

Both invocations must use the same `--seed` and size flags. `write` is idempotent
across reboots (it resumes from the committed index).

`verify --expect-committed <N>` supplies an off-volume floor on the committed op
index. The on-volume commit slots live on the same volume being shrunk, so fsck can
clear them along with the last files' data — which would make the verifier expect
nothing and mask the loss. Since the soak harness runs `write` to completion before
the shrink, it knows the true high-water mark and passes it here, so the last work is
still expected (and its loss flagged).

## Build

```sh
make build                       # docker image lfedge/evetest-volverify:1.0
GOWORK=off go test ./...         # unit tests (fault-injection classification)
sudo ./scripts/loopback-ext4-test.sh   # on-fs fidelity check (real ext4 + e2fsck)
```

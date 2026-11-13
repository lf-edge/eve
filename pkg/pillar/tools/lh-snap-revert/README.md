# lh-snap-revert

`lh-snap-revert` reverts the Longhorn volume behind an EVE-K app's PVC to one
of its snapshots, in place. The PVC, its UID and the PV are kept, so the app
uses the reverted data when it starts again.

This is an out-of-band recovery tool for occasional use. It:

- reverts a volume
- shows the snapshot branch that a revert leaves behind
- helps delete it, so that a later revert stays possible
- only changes the Longhorn volume, and does not manage the app state

Scheduling, retention and backup of snapshots stay with Longhorn and EVE.
The responsibility of stopping the application stays with the controller.

EVE-K images include it in the pillar container as
`/opt/zededa/bin/lh-snap-revert`. It is also a standalone binary, so it can be
built and copied to an EVE-K node of an older release that runs Longhorn
v1.9.1.

## Requirements

- An EVE-K cluster running Longhorn v1.9.1. On another version, `revert`
  prints a warning and exits, unless `--ignore-longhorn-version` is passed.
  Then it warns and continues. Check the tool against that Longhorn version
  first.
- Shell access to one cluster node, for example with `debug.enable.ssh`
  (see [CONFIG-PROPERTIES.md](../../../../docs/CONFIG-PROPERTIES.md)).

## Procedure

1. **Pause the snapshot schedule.** Note the current value of
   `storage.longhorn.snapshot.cron`, then set it to an empty value on every
   cluster node. EVE then deletes its recurring snapshot job. The existing
   snapshots stay. Set it on every node, because a node that keeps the old
   value can create the job again when it restarts.

   While the app runs, the job keeps only the newest 3 snapshots and
   deletes older ones. Without the pause, the snapshot to revert to can be
   deleted while you work through these steps. After the revert, the target
   is the parent of the current data. If the job deletes it before step 6,
   Longhorn cannot purge it and keeps the volume attached. See
   [Snapshot branches](#snapshot-branches).

   On a node, this shows no `default-eve-kube-app-snapshot` when the pause
   is in effect:

   ```sh
   eve exec kube kubectl -n longhorn-system get recurringjobs.longhorn.io
   ```

2. **Deactivate the app instance** from the controller. Pillar deletes the
   app's VMIRS and Longhorn detaches its volumes. Longhorn does not run
   recurring snapshot jobs on a detached volume.

3. **Run the tool** on one cluster node.

   ```sh
   ssh root@<node>
   eve exec pillar /opt/zededa/bin/lh-snap-revert pvcs            # find the PVC
   eve exec pillar /opt/zededa/bin/lh-snap-revert list --pvc <pvc>   # pick a snapshot
   eve exec pillar /opt/zededa/bin/lh-snap-revert revert --pvc <pvc> --snapshot <snap> --dry-run
   eve exec pillar /opt/zededa/bin/lh-snap-revert revert --pvc <pvc> --snapshot <snap>
   ```

   If the node's EVE release does not include the tool, build it and copy
   it to `/persist`, then run `/persist/lh-snap-revert` instead:

   ```sh
   make lh-snap-revert ZARCH=amd64        # or ZARCH=arm64; output: dist/<arch>/lh-snap-revert
   scp dist/amd64/lh-snap-revert root@<node>:/persist/
   ```

   Without Docker, `make -C pkg/pillar lh-snap-revert ZARCH=amd64` builds it
   with the host's Go toolchain into `pkg/pillar/dist/amd64/`.

   EVE names a volume's PVC `<volume UUID>-pvc-<generation>`. An app with
   several disks has one PVC per disk. Revert each PVC to a snapshot from the
   same point in time.

4. **Activate the app instance** from the controller.

5. **Check the data** inside the app.

6. **Delete the old branch.** When the data is correct, run
   `lh-snap-revert cleanup --pvc <pvc>` while the app runs. See
   [Snapshot branches](#snapshot-branches).

7. **Restore the snapshot schedule.** Set
   `storage.longhorn.snapshot.cron` on every node back to the value from
   step 1. The default is `0 0 * * *`.

## Commands

| Command | Purpose |
| ------- | ------- |
| `pvcs` | List PVCs with their Longhorn volume, size, state, recurring job hold and users |
| `list --pvc NAME` | Show the volume's snapshot tree, oldest first, with branches and snapshots that Longhorn cannot purge |
| `revert --pvc NAME --snapshot NAME` | Revert the volume to the snapshot |
| `cleanup --pvc NAME` | Delete the snapshots off the current branch. Run it while the app runs |

All commands accept `--kubeconfig` (default `/run/.kube/k3s/k3s.yaml`) and
`-n`/`--namespace` (default `eve-kube-app`). `cleanup` also accepts
`--dry-run` and `--yes`. `revert` also accepts:

| Flag | Meaning |
| ---- | ------- |
| `--dry-run` | Run all checks, print the plan and exit |
| `--yes` | Do not ask for confirmation |
| `--node NAME` | Longhorn node to attach on. Default: a Ready node that holds a replica |
| `--no-safety-snapshot` | Skip the safety-net snapshot |
| `--ignore-longhorn-version` | Run on a Longhorn version other than v1.9.1, with a warning |
| `--timeout D` | Limit for each wait and for the revert call (default `5m`) |

## What revert does

First it checks, without changing anything, that:

- the Longhorn version is v1.9.1, unless the version check is overridden
- the PVC is Bound to a Longhorn PV
- no pod, VMIRS or VMI uses the PVC
- the volume is detached with no attachment tickets and no CSI
  VolumeAttachment
- the snapshot exists and is ready

Then it runs these steps, numbered as in its output:

1. Holds the recurring jobs of the volume. Longhorn runs recurring jobs on
   an attached volume, also with the frontend disabled, and a snapshot job
   can delete old snapshots. The tool sets each `recurring-job.longhorn.io/*`
   and `recurring-job-group.longhorn.io/*` label of the Longhorn volume that
   is `enabled` to `disabled`, and records them in the volume annotation
   `lh-snap-revert/held-recurring-jobs`. A volume without these labels gets
   `recurring-job-group.longhorn.io/default=disabled`. Other volumes and the
   cluster schedule do not change.
2. Creates a safety-net snapshot `lh-snap-revert-<UTC time>` of the current
   data, and waits until Longhorn detaches the volume again. Longhorn
   attaches the volume for the snapshot with the frontend enabled. The
   Longhorn v1.9.1 engine crashes on a snapshot while its frontend is
   disabled, so the tool takes the snapshot before it attaches.
3. Attaches the volume with the frontend disabled, using its own
   `lh-snap-revert` attachment ticket.
4. Checks the hold and the target snapshot again.
5. Reverts the volume through the Longhorn API.
6. Removes its ticket, waits for the volume to detach, sets the held labels
   back to `enabled` and removes the annotation.
7. Checks that the PVC UID and PV did not change.

From step 1 on, any failure or Ctrl-C detaches the volume and restores the
recurring jobs. A Ctrl-C during the revert call takes effect when the call
returns. A second Ctrl-C stops the tool at once and leaves the volume as it
is; use the recovery commands below.

`revert` refuses a PVC with the label
`recurring-job.longhorn.io/source=enabled`. With it, Longhorn copies the
PVC's recurring job labels to the volume and undoes the hold. EVE does not
set this label.

## Exit codes and recovery

| Code | Meaning |
| ---- | ------- |
| 0 | Reverted. The app can be activated |
| 1 | Refused or failed before attaching. The volume data did not change. If the output prints a command to delete a pending safety-net snapshot or to restore recurring jobs, run it |
| 2 | Failed after attaching. The `reverted:` line says `yes`, `no` or `unknown` |

The table describes `revert`. The other commands exit 0 on success and 1 on
any error.

If the ticket could not be removed, the tool prints the command to remove it
by hand. It first retries the detach during cleanup, so this can take up to
twice `--timeout`. Run the command in the same shell on the node:

```sh
eve exec kube kubectl -n longhorn-system patch volumeattachments.longhorn.io <volume> --type merge \
  -p '{"spec":{"attachmentTickets":{"lh-snap-revert":null}}}'
```

If the safety-net snapshot did not become ready, Longhorn keeps retrying it
and holds the volume with its own ticket, and the next `revert` refuses to
run. The tool prints the command to delete the snapshot:

```sh
eve exec kube kubectl -n longhorn-system delete snapshots.longhorn.io <snapshot> --wait=false
```

If the recurring jobs could not be restored, the tool prints a `kubectl patch`
command that restores them. `pvcs` shows `held` in the JOBS column for a
volume that a run left held. The next `revert` of that volume that passes its
checks also restores them.

If `revert` refuses because the volume is attached, the error names each
attachment ticket that holds the volume and what it belongs to.

## Snapshot branches

A revert starts a new branch. The current data continues from the target
snapshot. The snapshots that held the data before the revert, the
safety-net snapshot included, stay on an old branch. `list` marks them
`old branch`:

```text
NAME                CREATED               SIZE       ORIGIN     STATE
X                   2026-11-01T00:00:15Z  4.0 GiB    recurring  ready
|- default--6920…   2026-11-02T00:00:12Z  1.0 GiB    recurring  old branch, ready
|  lh-snap-revert-… 2026-11-03T23:03:25Z  640.0 KiB  user       old branch, ready
`- default--c14f…   2026-11-04T00:00:20Z  512.0 MiB  recurring  ready
   volume-head                            -          -          current data
```

To undo the revert, revert to the safety-net snapshot. When the data is
confirmed, run `cleanup` while the app runs. It lists the snapshots off the
current branch, asks for confirmation and deletes them. Longhorn updates the
tree only while the volume is attached, so `cleanup` refuses to run on a
detached volume.

Do not leave the old branch in place. The Longhorn engine cannot purge a
snapshot that has more than one child, such as X. When X is deleted, for
example by the recurring snapshot job, Longhorn can keep the volume attached
until one branch below it is deleted. The app still runs, but the volume
cannot be detached, and `revert` refuses to run. `list` shows such a
snapshot as `deleting, 2 children, cannot be purged`, and `cleanup` clears
it.

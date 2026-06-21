# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# shellcheck shell=sh
#
# Boot-disk repartition helpers, driving the storage-resizer binary.
# Sourced by storage-init.sh (not executed standalone) and relies on CONFIGDIR,
# PERSISTDIR and log() defined there.
#
# baseosmgr (online) decides the boot disk needs the larger ESP/IMGA/IMGB layout,
# writes the /config/repartition-inprogress flag file (its value is the shrink
# target size, or "grow-only" when no shrink is needed), and reboots. On the
# shrink path it first backs up the connectivity- and device-identity-critical
# files to the CONFIG partition. Here, with /persist still unmounted, we run the
# offline shrink+grow (or grow-only); after /persist is mounted we restore
# anything a shrink lost and clean up. The grow always runs offline because the
# boot disk's partition table cannot be re-read live while its rootfs is mounted.
# See pkg/pillar/docs/diskconvert.md and pkg/storage-resizer/README.md.

# disk_of_partlabel echoes the whole-disk device (e.g. /dev/sda) carrying the
# partition with the given GPT label, or nothing if not found.
disk_of_partlabel() {
    _part=$(findfs PARTLABEL="$1") || return 1
    [ -n "$_part" ] || return 1
    _sys=$(echo /sys/block/*/"${_part#/dev/}")
    echo "/dev/$(echo "$_sys" | cut -f4 -d/)"
}

# Resize fail-safe knobs/helpers.
# storage-resizer exits 64 when it committed the new GPT to disk but the kernel
# could not re-read it live (busy boot disk) -- reboot to apply.
#
# Two non-success outcomes, with opposite lifecycles:
#   resize_reboot (exit 64) -- REPEAT. The repartition-inprogress flag is left in place,
#     so the next boot re-runs the resize; the resize-reboots counter bounds this
#     loop (resize_abort "too-many-reboots" once it reaches RESIZE_MAX_REBOOTS).
#   resize_abort (any other failure) -- TERMINAL for this running image. Writes the
#     resize-failed.json marker (with eve_release) and reboots, but deliberately
#     leaves the flag, backup, and counter in place: the retained backup lets the
#     abort boot recover device identity if a destructive shrink corrupted /persist
#     (the P3-mount fsck recreates it, then maybe_restore_after_persist restores),
#     and the eve_release-matched marker -- not the flag -- is what stops the retry
#     (maybe_offline_disk_resize skips while a marker for this running image exists).
#     baseosmgr reports the decline and clears the marker when the running image
#     changes (a new image may carry a fixed resizer) or the target is withdrawn.
RESIZE_REBOOT_TO_APPLY=64
RESIZE_MAX_REBOOTS=5

# _mount_config_rw mounts the CONFIG partition read-write at $1. The runtime
# /config is a read-only tmpfs RAM copy, so durable writes (failure marker,
# reboot counter, flag/backup removal) must land on the partition. Returns
# non-zero if the partition can't be found or mounted.
_mount_config_rw() {
    _cfgp=$(findfs PARTLABEL=CONFIG) || return 1
    [ -n "$_cfgp" ] || return 1
    mkdir -p "$1"
    mount -t vfat -o rw,iocharset=iso8859-1 "$_cfgp" "$1"
}

# _running_eve_release echoes the running rootfs EVE version, stripped of any
# trailing newline. /etc/eve-release is baked into the rootfs and is visible here
# as /hostfs/etc/eve-release (cf. /hostfs/etc/eve-hv-type read by storage-init.sh);
# it equals the runtime /run/eve-release that pillar/baseosmgr compares against.
_running_eve_release() {
    tr -d '\r\n' < /hostfs/etc/eve-release 2>/dev/null
}

# _marker_eve_release echoes the eve_release field from a resize-failed.json marker
# at $1. The marker is our own single-line JSON, so a targeted extract suffices
# (there is no JSON parser available this early in boot).
_marker_eve_release() {
    sed -n 's/.*"eve_release":"\([^"]*\)".*/\1/p' "$1" 2>/dev/null
}

# resize_reboot reboots from early boot (no pillar/nodeagent yet) to apply a
# committed-but-not-yet-kernel-visible GPT, or to recover after a clean abort.
# storage-init has all capabilities and /proc, so try reboot(2), then magic
# sysrq, then a forced reboot; never fall through into a half-resized mount.
# NB: confirm on-device that reboot(2) from this onboot container reboots the
# host (vs only the container) and adjust if sysrq is the reliable path.
resize_reboot() {
    sync
    reboot 2>/dev/null || true
    sleep 5
    echo b > /proc/sysrq-trigger 2>/dev/null || true
    sleep 10
    reboot -f 2>/dev/null || true
    log "storage-resizer: FATAL: could not reboot; halting to avoid an inconsistent disk"
    while : ; do sleep 3600; done
}

# resize_abort records a failure marker on the CONFIG partition (the only durable
# store this early) and reboots into a clean, manageable system on the unchanged
# layout. It deliberately LEAVES the shrink flag, backup, and reboot counter in
# place: a destructive shrink can corrupt /persist (resize2fs/e2fsck are not
# transactional), so the retained backup lets the abort boot recover identity once
# the P3-mount fsck recreates /persist and maybe_restore_after_persist restores it.
# The retry is stopped by the marker (matched on eve_release) in
# maybe_offline_disk_resize, not by destroying the backup. baseosmgr reads the
# marker, reports the decline, and clears it on an image change / target
# withdrawal. A failed resize must degrade to a clean upgrade-decline, never a brick.
resize_abort() {
    _ad=/tmp/config_abort
    if _mount_config_rw "$_ad"; then
        printf '{"eve_release":"%s","step":"%s","rc":"%s","ts":"%s"}\n' \
            "$(_running_eve_release)" "$1" "$2" "$(date -Ins -u)" > "$_ad/resize-failed.json" 2>/dev/null
        sync
        umount "$_ad"
    else
        log "storage-resizer: could not mount CONFIG rw to record resize failure ($1 rc=$2)"
    fi
    resize_reboot
}

# maybe_offline_disk_resize runs the shrink+grow while /persist is unmounted, gated
# on the shrink flag file baseosmgr left on the CONFIG copy. The shrink cannot run
# with /persist mounted and, in the worst case (an unrecoverable fs), can lose
# /persist -- hence the prior backup and the restore below; the grow is never
# destructive. Each step re-plans from the live GPT, so a crash is recovered by
# re-running on the next boot. Non-success outcomes can never brick the device:
# exit 64 means the GPT is committed but the kernel re-read was deferred (busy
# disk) -> reboot to apply (the next boot's resize is a no-op); any other non-zero
# exit aborts cleanly. A bounded reboot counter guards a non-converging loop.
maybe_offline_disk_resize() {
    [ -f "$CONFIGDIR/repartition-inprogress" ] || return 0
    # Do not retry a resize that already failed under THIS running image: it would
    # fail identically (deterministic, the resizer is the running image's) and each
    # attempt costs a reboot. The marker is reported by baseosmgr and cleared when
    # the running image changes (a new image may carry a fixed resizer) or the
    # controller withdraws the target. A marker from a different eve_release is
    # stale (left from a previous image) -- ignore it and attempt normally.
    if [ -f "$CONFIGDIR/resize-failed.json" ] &&
       [ "$(_marker_eve_release "$CONFIGDIR/resize-failed.json")" = "$(_running_eve_release)" ]; then
        log "storage-resizer: prior resize failed under this image ($(_running_eve_release)); not retrying (resize-failed.json present)"
        return 0
    fi

    # We are now committed to a resize attempt. Keep the hardware watchdog fed for
    # the whole attempt: the shrink/grow can run longer than the watchdog timeout,
    # and where firmware armed the watchdog the kernel only feeds it until
    # open_timeout elapses. Hold and pet /dev/watchdog from here until the resize
    # is done (killed below, which disarms it); the resize_reboot/resize_abort
    # paths reset the device, which stops the feeder regardless.
    storage-resizer run-watchdog --timeout 60 >/dev/console 2>&1 &
    _wd_pid=$!

    _bootdev=$(disk_of_partlabel IMGA) || _bootdev=""
    if [ -z "$_bootdev" ]; then
        log "storage-resizer: cannot find boot disk (IMGA); aborting resize"
        resize_abort "find-bootdisk" "1"
    fi

    # bound the resize->reboot loop using a counter on the CONFIG partition
    _n=$(cat "$CONFIGDIR/resize-reboots" 2>/dev/null || echo 0)
    case "$_n" in ''|*[!0-9]*) _n=0 ;; esac
    if [ "$_n" -ge "$RESIZE_MAX_REBOOTS" ]; then
        log "storage-resizer: resize did not converge after $_n reboots; aborting"
        resize_abort "too-many-reboots" "$_n"
    fi
    _cd=/tmp/config_count
    if _mount_config_rw "$_cd"; then
        echo $((_n + 1)) > "$_cd/resize-reboots" 2>/dev/null
        sync
        umount "$_cd"
    fi

    # The flag value is the shrink target size, or the literal "grow-only" when
    # baseosmgr armed a no-shrink repartition (the boot disk already has a free
    # tail). Skip the shrink in the grow-only case; the grow runs the same either
    # way. The grow always runs offline because the boot disk's partition table
    # cannot be re-read live while its rootfs is mounted.
    _mode=$(tr -d '\r\n' < "$CONFIGDIR/repartition-inprogress" 2>/dev/null)
    if [ "$_mode" = "grow-only" ]; then
        log "storage-resizer: grow-only requested on $_bootdev (attempt $((_n + 1)))"
    else
        log "storage-resizer: shrink+grow requested on $_bootdev (attempt $((_n + 1)))"
        storage-resizer shrink --disk "$_bootdev" --flag-file "$CONFIGDIR/repartition-inprogress" --fix-errors >/dev/console 2>&1
        _rc=$?
        if [ "$_rc" -eq "$RESIZE_REBOOT_TO_APPLY" ]; then
            log "storage-resizer: shrink committed the GPT; rebooting to apply"
            resize_reboot
        elif [ "$_rc" -ne 0 ]; then
            log "storage-resizer: shrink failed (rc=$_rc) on $_bootdev; aborting resize"
            resize_abort "shrink" "$_rc"
        fi
    fi
    storage-resizer grow --disk "$_bootdev" --fix-errors >/dev/console 2>&1
    _rc=$?
    if [ "$_rc" -eq "$RESIZE_REBOOT_TO_APPLY" ]; then
        log "storage-resizer: grow committed the GPT; rebooting to apply"
        resize_reboot
    elif [ "$_rc" -ne 0 ]; then
        log "storage-resizer: grow failed (rc=$_rc) on $_bootdev; aborting resize"
        resize_abort "grow" "$_rc"
    fi
    partprobe "$_bootdev"
    [ -n "${_wd_pid:-}" ] && kill "$_wd_pid" 2>/dev/null   # disarms the watchdog (magic close)
    log "storage-resizer: repartition complete on $_bootdev"
}

# resync_inmem_config removes from the read-only tmpfs /config the same resize
# bookkeeping files that cleanup just removed from the CONFIG partition. Without
# this the tmpfs still carries repartition-inprogress/backup-persist while the partition
# does not, so measure-config (which runs after storage-init and measures the
# in-memory /config into PCR14) records a value that the next boot -- whose tmpfs
# is rebuilt from the now-clean partition -- will not reproduce, forcing a
# controller-key unlock with MismatchingPCRs [14]. Mirroring the deletes here, on
# the same boot before measure-config, keeps PCR14 at its steady-state value and
# preserves the local TPM unseal. The tmpfs is remounted ro afterwards to match
# how the boot left it.
#
# resize-failed.json is intentionally NOT removed here: baseosmgr owns its
# lifecycle (reads, reports, clears it). It is left consistent on BOTH the
# partition and the tmpfs, so its presence does not churn PCR14 between boots.
resync_inmem_config() {
    [ -e "$CONFIGDIR/repartition-inprogress" ] || [ -e "$CONFIGDIR/backup-persist" ] || \
        [ -e "$CONFIGDIR/resize-reboots" ] || return 0
    mount -o remount,rw "$CONFIGDIR" || { log "storage-resizer: remount /config rw failed; PCR14 may churn"; return 1; }
    rm -f "$CONFIGDIR/repartition-inprogress" "$CONFIGDIR/resize-reboots"
    rm -rf "$CONFIGDIR/backup-persist"
    sync
    mount -o remount,ro "$CONFIGDIR"
}

# maybe_restore_after_persist restores the backed-up files into the freshly mounted
# /persist (needed only when the shrink had to recreate /persist empty) and then
# cleans up. It mounts the CONFIG partition READ-WRITE because the runtime
# /config is a read-only tmpfs RAM copy whose writes are lost on reboot, so the
# flag/backup removal must land on the real partition. After cleaning the
# partition it also re-syncs the in-memory /config (resync_inmem_config) so PCR14
# stays stable this boot. Skipped when there is nothing to do (no flag and no
# leftover backup dir in the CONFIG copy).
maybe_restore_after_persist() {
    [ -e "$CONFIGDIR/repartition-inprogress" ] || [ -e "$CONFIGDIR/backup-persist" ] || return 0
    _cfgpart=$(findfs PARTLABEL=CONFIG) || _cfgpart=""
    if [ -z "$_cfgpart" ]; then
        log "storage-resizer: no CONFIG partition; cannot restore/cleanup"
        return 1
    fi
    _cfgrw=/tmp/config_rw
    mkdir -p "$_cfgrw"
    if ! mount -t vfat -o rw,iocharset=iso8859-1 "$_cfgpart" "$_cfgrw"; then
        log "storage-resizer: mount $_cfgpart rw failed"
        return 1
    fi
    # restore self-gates on the flag file: present -> restore the files the shrink
    # lost (missing, empty, or invalid for their type) then remove the flag file
    # (first) and the backup dir; absent -> GC any leftover backup dir. cleanup is
    # the idempotent sweep for a crash that cleared the flag but left the dir; it
    # refuses while the flag is still present.
    # If the P3-mount step had to reformat /persist (INIT_FS=1), a destructive
    # shrink wiped it; tell restore to stamp persist_recreated into the marker so
    # baseosmgr can report that workloads were lost (identity is restored here).
    _pr_flag=""
    [ "$INIT_FS" = 1 ] && _pr_flag="--persist-recreated"
    # shellcheck disable=SC2086 # _pr_flag is a single optional token, intentional split
    storage-resizer restore --persist "$PERSISTDIR" \
        --backup-dir "$_cfgrw/backup-persist" --flag-file "$_cfgrw/repartition-inprogress" \
        --failure-marker "$_cfgrw/resize-failed.json" $_pr_flag --cleanup >/dev/console 2>&1
    storage-resizer cleanup \
        --backup-dir "$_cfgrw/backup-persist" --flag-file "$_cfgrw/repartition-inprogress" >/dev/console 2>&1
    # the resize reached the post-persist restore/cleanup stage, so clear the
    # resize->reboot bound counter. resize-failed.json is intentionally LEFT for
    # baseosmgr to read, report, and clear (on an image change / target withdrawal).
    rm -f "$_cfgrw/resize-reboots"
    sync
    umount "$_cfgrw"
    # mirror the partition deletes onto the in-memory /config so PCR14 (measured
    # later this boot) matches the steady state and the local unseal is preserved
    resync_inmem_config
}

# Measuring the CONFIG partition into PCR 14

EVE measures the contents of the CONFIG partition into TPM PCR 14 on every boot. PCR 14 is part of the vault key access control policy described in [SECURITY-ARCHITECTURE](SECURITY-ARCHITECTURE.md), so a change to any measured file means the vault key no longer unseals: `/persist/vault` stays unavailable until the controller accepts the new measurements and releases the encrypted backup key. This document describes what that measurement covers, which is what determines whether a given local modification is detected.

The measurement is performed by [pkg/measure-config](../pkg/measure-config/src/measurefs.go), which runs as the last `onboot` container in [images/rootfs.yml.in](../images/rootfs.yml.in) — after every other container that can modify `/config`. On a device without a TPM it does nothing.

## What is measured

`/config` is walked recursively and the resulting list of files is sorted by path, so that devices with identical content produce identical PCR values regardless of on-disk layout. For each file one `TPM2_PCR_Event` extends PCR 14 with a line of text:

```text
file:/config/server exist:true content-hash:<sha256 of the file contents>
```

Directories are not measured. A path longer than 512 bytes is replaced by its base name, because `TPM2_PCR_Event` accepts at most 1024 bytes of event data.

### Files whose content is not measured

The content of seven files is excluded, because each is unique to the device or is written during normal operation:

```text
/config/tpm_credential      /config/device.cert.pem    /config/device.key.pem
/config/onboard.cert.pem    /config/onboard.key.pem    /config/soft_serial
/config/ftpm.tar.xz
```

Their presence or absence is still measured, so deleting one of them does change PCR 14. For these files the event line carries existence only:

```text
file:/config/device.cert.pem exist:true
```

A consequence of measuring their presence is that PCR 14 differs between a freshly installed device and the same device once it has generated its certificates, and between a live image and an installed one.

### Files measured as absent

Three paths are measured even when they do not exist:

```text
/config/bootstrap-config.pb
/config/DevicePortConfig/override.json
/config/GlobalConfig/global.json
```

These, and the excluded files above, are seeded into the file list on every device, so the event log has the same shape everywhere. One of these files appearing later therefore shows up as a changed measurement rather than as a longer log.

### Everything else

Every other file in `/config` is measured with its content, including `/config/server`, `/config/remote_access_disabled`, `/config/authorized_keys` and the pinned controller root certificates. A local edit to any of them is detected at the next boot and leaves the vault sealed.

## The event log

Each measurement is also recorded in `/persist/status/measurefs_tpm_event_log` in the TCG Crypto Agile Log Entry Format, as an `EV_EFI_ACTION` (`0x80000007`) event whose digest is the SHA-256 of the event line. The log is rewritten on every boot.

At the point the vault key is sealed, pillar appends this log to the firmware event log read from `/hostfs/sys/kernel/security/tpm0/binary_bios_measurements` and stores the combined result in `/persist/status/tpm_measurement_seal_success`. If a later unseal fails, the same combination is written to `/persist/status/tpm_measurement_unseal_fail`, and the previous pair is preserved first — recovering a device involves reconnecting to the controller and sealing again, which would otherwise overwrite the copy the diff needs.

Comparing the two logs identifies which `/config` file changed, rather than only that PCR 14 moved. The set of PCRs in force at the last seal is recorded separately in `/persist/status/sealingpcrs`, which is what lets EVE report the mismatching PCRs when an unseal fails.

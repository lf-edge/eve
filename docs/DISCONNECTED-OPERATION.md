# Operating Without the Controller

An edge node is expected to lose its controller — a WAN outage, a controller
maintenance window, a site that is connected only intermittently by design.
This document describes what an EVE device does during such a period: what
keeps running, what an operator can still change locally, what bounds the
duration, and what is unavailable until the connection returns. The mechanisms
themselves are documented per agent in
[nodeagent](../pkg/pillar/docs/nodeagent.md) and
[zedagent](../pkg/pillar/docs/zedagent.md); this is the device-level view.

## Applications keep running

Nothing about the loss of the controller stops application instances, and
nothing expires the configuration they run under. EVE applies the
configuration it holds and does not require the controller to reaffirm it.

The same is true across a power failure. EVE keeps the last successfully
applied configuration in `/persist/checkpoint/lastconfig` and replays it at
boot, before the controller has been reached. No age limit applies to that
checkpoint: a device that has been disconnected for months boots into the
configuration it last received. The one substitution EVE makes is for its own
protection — when the previous boot ended in a panic or watchdog reset, the
backup checkpoint is used instead of the primary, so a configuration that
crashes the device cannot drive a reboot loop.

Encrypted storage needs no controller either. The vault key unseals from the
TPM against the PCR values it was sealed to, which is a local operation. A
device therefore returns to service unattended, provided nothing changed the
measurements in the meantime — a firmware update, a change to the CONFIG
partition (see [MEASURED-CONFIG](MEASURED-CONFIG.md)), or replaced hardware.
When measurements have changed the vault stays sealed and the device needs its
controller, which is the designed behavior and is described in
[SECURITY-ARCHITECTURE](SECURITY-ARCHITECTURE.md).

Device identity does not age out: the device certificate is issued for twenty
years, so no realistic outage outlasts it.

## Local control while disconnected

Two optional local paths remain available, and they differ in what they are
trusted to do (see [LPS](LPS.md)):

* A **Local Operator Console** substitutes for the controller and serves the
  entire device configuration. The configuration it serves is signed by the
  controller, so a LOC distributes controller-authored configuration rather
  than authoring its own.
* A **Local Profile Server** complements the controller with local operations —
  selecting a profile, restarting an application, radio silence, graceful
  shutdown. It is authenticated by a token the controller provisioned to the
  device beforehand, and its requests are not signed.

The [local TUI](LOCAL-TUI.md) remains available to a physically present
operator for network configuration, which is often what an outage calls for.

## What bounds the outage

Three limits apply. Only the first is a choice.

### Reboot after prolonged disconnection

`timer.reboot.no.network` (seven days by default, see
[CONFIG-PROPERTIES](CONFIG-PROPERTIES.md)) reboots the device when the
controller has been unreachable for that long. This is recovery machinery
rather than a policy limit on disconnected operation: a hung network
interface, driver or firmware is not reliably detectable from userspace, and a
restart is the one remedy available to a device that cannot be reached to be
told anything.

The tradeoff is explicit. A deployment that values uninterrupted application
uptime over automatic recovery from a wedged interface should raise the value;
a deployment of remote unattended nodes generally should not.

### Log history is capped

Logs accumulate on disk while they cannot be uploaded, bounded by
`newlog.gzipfiles.ondisk.maxmegabytes` (2 GB by default) and additionally by
10% of the `/persist` partition, whichever is smaller. Above the cap the
oldest files are deleted first, and the queues are consumed in order:
already-uploaded, upload-failed, application, device. Records produced during
the outage are the last to be discarded — but on a busy device during a long
outage they are discarded, and they are the records an operator most wants
afterwards. Raise the quota on nodes expected to run disconnected. See
[LOGGING](LOGGING.md).

### Time must be correct before remote fetches work

A controller outage does not affect time synchronization, which uses its own
servers (see [CLOCK-SYNCHRONIZATION](CLOCK-SYNCHRONIZATION.md)). A device
whose real-time clock is unreliable and that was also cut off from NTP needs
to resynchronize before it can fetch anything remote. TLS tolerates a fair
amount of clock error; the datastore protocols images are downloaded through
are markedly less forgiving, so downloads are the first thing to fail on a
device with a bad clock and the last to recover.

## What is unavailable

Configuration changes do not reach the device, and device state, metrics and
logs do not reach the operator. Deploying a new application, updating the base
image and rotating credentials all wait for the connection. EdgeView sessions
are brokered by the controller and cannot be established.

This is an availability property, not a weakening of the device's security
posture. While disconnected, the vault remains sealed to the state it was
sealed in, and no new configuration, application or base image can be
introduced by anyone — including an attacker who has taken the controller's
place at the network level, since configuration must still carry a signature
chaining to the roots in the CONFIG partition.

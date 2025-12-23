# VM Boot Order Configuration

This document describes how to configure the boot order for virtual machines (
VMs) running on EVE, with a focus on USB boot priority control.

## Overview

By default, UEFI-based VMs prioritize USB devices in their boot order according
to the UEFI specification. EVE provides runtime control over VM boot order
<<<<<<< HEAD
through the **Local Profile Server (LPS)** API, allowing operators to enable or
disable USB boot priority on a per-application basis without modifying firmware
files.
=======
through three mechanisms:

1. **Controller API**: The `boot_order` field in `VmConfig` allows setting boot
   order as part of the application configuration from the controller.
2. **Local Profile Server (LPS)**: The `/api/v1/app-boot-config` endpoint allows
   runtime boot order changes without modifying the controller configuration.
3. **Device Configuration Property**: The `app.boot.order` property sets a
   device-wide default boot order for all VMs.

All mechanisms allow operators to enable or disable USB boot priority without
modifying firmware files.

## Configuration Precedence

When multiple boot order sources are configured, EVE applies them in the
following priority order (highest to lowest):

1. **LPS boot order** - Takes highest priority if configured (per-VM)
2. **Controller API boot order** - Per-VM setting via `VmConfig.boot_order`
3. **Device configuration property** - Device-wide default via `app.boot.order`
4. **Default OVMF behavior** - Used when no configuration is specified

This allows operators to:

- Set a device-wide default boot order via device configuration property
- Override the default for specific VMs via Controller API
- Further override via LPS for special cases or air-gapped environments
- Fall back to firmware defaults when no configuration is specified

## Controller API Boot Order

The Controller API provides boot order configuration through the `boot_order`
field in the `VmConfig` message within `AppInstanceConfig`.

### Configuration

The `boot_order` field is set at application deployment time and can be modified
by updating the application configuration:

```protobuf
// BootOrder enum defined in evecommon/evecommon.proto
enum BootOrder {
  BOOT_ORDER_UNSPECIFIED = 0;  // Default boot order (no modification)
  BOOT_ORDER_USB = 1;          // Prioritize USB devices in boot order
  BOOT_ORDER_NOUSB = 2;        // Remove USB devices from boot order
}

message VmConfig {
  // ... other fields ...

  // Boot order configuration for the VM.
  org.lfedge.eve.common.BootOrder boot_order = 27;
}
```

### Controller API Behavior

- Boot order is applied when the VM starts
- Changes require a VM restart to take effect
- The setting persists until the application configuration is updated
- Can be overridden by LPS configuration

## Device Configuration Property

The `app.boot.order` device configuration property sets a device-wide default
boot order for all VMs. This is useful when all VMs on a device should have
the same boot order setting.

### Device Property

The property is set via the controller's device configuration:

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `app.boot.order` | string | `""` | Device-wide default boot order. Values: `""`, `"usb"`, `"nousb"` |

### Device Property Behavior

- Provides a device-wide default for all VMs
- Consulted at VM creation time if no per-app setting is configured
- Overridden by Controller API per-app setting (`VmConfig.boot_order`)
- Further overridden by LPS per-app setting
- Changes take effect on next VM start
- See [CONFIG-PROPERTIES.md](CONFIG-PROPERTIES.md) for more device properties
>>>>>>> d881b77af (fixup! docs: add VM boot order configuration documentation.)

## LPS-Controlled Boot Order

EVE implements per-VM boot order control through the LPS
`/api/v1/app-boot-config` endpoint. This approach provides per-VM granularity
where different VMs can have different boot order settings. Configuration is
managed via LPS which makes it suitable for air-gapped deployments. Settings are
persisted and survive EVE reboots. Changes take effect on the next VM restart.

## How It Works

### Architecture

```text
<<<<<<< HEAD
┌─────────────────────────────────────────────────────────────────────┐
│                     Local Profile Server (LPS)                      │
│                                                                     │
│  GET /api/v1/app-boot-config returns:                              │
│  {                                                                  │
│    "server_token": "...",                                          │
│    "app_configs": [                                                │
│      { "id": "vm-uuid", "usb_boot": "nousb" }                      │
│    ]                                                                │
│  }                                                                  │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼ HTTP GET (every 10s)
┌─────────────────────────────────────────────────────────────────────┐
│                              EVE                                    │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │  zedagent    │───▶│  domainmgr   │───▶│  KVM/Xen hypervisor  │  │
│  │              │    │              │    │                      │  │
│  │ Fetches LPS  │    │ Stores boot  │    │ Passes boot order    │  │
│  │ config       │    │ order in     │    │ to QEMU via fw_cfg   │  │
│  │              │    │ DomainConfig │    │                      │  │
│  └──────────────┘    └──────────────┘    └──────────────────────┘  │
│                                                   │                 │
└───────────────────────────────────────────────────│─────────────────┘
=======
┌───────────────────────────────────────────────────────────────────┐
│                          Controller                               │
│                                                                   │
│  Device Property: app.boot.order = "nousb"  (device-wide default) │
│  App Config: apps[].fixedresources.boot_order = BOOT_ORDER_USB    │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
        │
        │ Config delivery
        │
        │       ┌───────────────────────────────────────────────────┐
        │       │         Local Profile Server (LPS)                │
        │       │             (Optional Override)                   │
        │       │                                                   │
        │       │  GET /api/v1/app-boot-config returns:             │
        │       │  {                                                │
        │       │    "server_token": "...",                         │
        │       │    "app_configs": [                               │
        │       │      { "id": "vm-uuid", "usb_boot": "BOOT_ORDER_NOUSB" }
        │       │    ]                                              │
        │       │  }                                                │
        │       └───────────────────────────────────────────────────┘
        │                          │
        │                          │ HTTP GET (every 10s)
        ▼                          ▼
┌───────────────────────────────────────────────────────────────────┐
│                              EVE                                  │
│                                                                   │
│  ┌──────────────┐    ┌──────────────┐    ┌────────────────────┐   │
│  │  zedagent    │───▶│  domainmgr   │───▶│ KVM/Xen hypervisor │   │
│  │              │    │              │    │                    │   │
│  │ Receives     │    │ Merges boot  │    │ Passes boot order  │   │
│  │ Controller + │    │ order:       │    │ to QEMU via fw_cfg │   │
│  │ LPS config   │    │ LPS > App >  │    │                    │   │
│  │              │    │ DeviceProp   │    │                    │   │
│  └──────────────┘    └──────────────┘    └────────────────────┘   │
│                                                   │               │
└───────────────────────────────────────────────────│───────────────┘
>>>>>>> d881b77af (fixup! docs: add VM boot order configuration documentation.)
                                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         QEMU (per VM)                               │
│                                                                     │
│  [fw_cfg]                                                          │
│    name = "opt/eve.bootorder"                                      │
│    string = "nousb"    # or "usb" or absent                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    OVMF Firmware (per VM)                           │
│                                                                     │
│  EveBootOrderLib reads opt/eve.bootorder:                          │
│  - "usb"   → Prioritize USB devices in boot order                  │
│  - "nousb" → Deprioritize USB devices in boot order                │
│  - absent  → Use default UEFI boot order                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Boot Order Values

| Value    | Effect                                                        |
|----------|---------------------------------------------------------------|
| `"usb"`  | USB devices are prioritized in the boot order                 |
| `"nousb"`| USB devices are deprioritized (disk boots first)              |
| `""`     | Default behavior (see "Default Behavior" section below)       |

### Default Behavior

When no boot order is explicitly configured (empty string or not specified),
the behavior depends on the OVMF firmware being used:

**Standard OVMF (no custom OVMF.fd)**: USB has priority according to the UEFI
specification. This is the traditional UEFI behavior where removable media is
checked first.

**Custom OVMF.fd**: When a custom `OVMF.fd` file is provided (currently used
for applications running in FML mode with custom framebuffer resolution),
the boot order is "precooked" into the firmware. The custom firmware's
built-in boot order takes precedence.

## Configuration via LPS

### API Endpoint

```http
GET /api/v1/app-boot-config
```

### Response Format

```json
{
  "server_token": "your-secret-token",
  "app_configs": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "displayname": "production-vm",
      "usb_boot": "BOOT_ORDER_NOUSB"
    },
    {
      "id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      "displayname": "deployment-vm",
      "usb_boot": "BOOT_ORDER_USB"
    }
  ]
}
```

### Field Descriptions

| Field         | Required | Description                                          |
|---------------|----------|------------------------------------------------------|
| `server_token`| Yes      | Must match the token configured in EdgeDevConfig     |
| `id`          | No*      | Application UUID                                     |
| `displayname` | No*      | User-friendly application name                       |
| `usb_boot`    | No       | Boot order enum: `BOOT_ORDER_USB`, `BOOT_ORDER_NOUSB`, or `BOOT_ORDER_UNSPECIFIED` |

*At least one of `id` or `displayname` must be provided.

### Behavior

Each LPS response represents the complete desired state. Applications NOT
included in the response will use default boot order. Sending the same
configuration multiple times has no effect. Changes take effect on the next VM
restart. Configuration is saved to disk and survives EVE reboots.

<<<<<<< HEAD
=======
**BOOT_ORDER_UNSPECIFIED handling**: When `usb_boot` is set to `BOOT_ORDER_UNSPECIFIED`
(or omitted), it means "no override" - the next priority level is used (Controller
API setting, then Device Property). This allows operators to selectively override
only specific apps via LPS while letting others use their configured values.

>>>>>>> d881b77af (fixup! docs: add VM boot order configuration documentation.)
### Throttling

Normal polling interval is every 10 seconds. When LPS returns 404, polling is
throttled to every 5 minutes.

## Deployment Scenarios

### Scenario 1: Configure Boot Order for Multiple VMs

```json
{
  "server_token": "...",
  "app_configs": [
    { "id": "vm1-uuid", "usb_boot": "BOOT_ORDER_NOUSB" },
    { "id": "vm2-uuid", "usb_boot": "BOOT_ORDER_USB" },
    { "id": "vm3-uuid", "usb_boot": "BOOT_ORDER_NOUSB" }
  ]
}
```

### Scenario 2: Reset to Default

To reset all VMs to default boot order, send an empty configuration:

```json
{
  "server_token": "...",
  "app_configs": []
}
```

Or to reset a specific VM while configuring others:

```json
{
  "server_token": "...",
  "app_configs": [
    { "id": "vm1-uuid", "usb_boot": "BOOT_ORDER_UNSPECIFIED" },
    { "id": "vm2-uuid", "usb_boot": "BOOT_ORDER_NOUSB" }
  ]
}
```

## Technical Details

### OVMF Integration

EVE uses a patched version of OVMF (TianoCore EDK2) that includes
`EveBootOrderLib`. This library reads the `opt/eve.bootorder` fw_cfg file from
QEMU during early boot, parses the value (`usb`, `nousb`, or empty), and adjusts
the UEFI boot order accordingly before the boot menu is displayed.

The patched OVMF is built as part of EVE's `pkg/uefi` package.

### QEMU fw_cfg

The boot order is passed to OVMF via QEMU's fw_cfg mechanism:

```ini
[fw_cfg]
  name = "opt/eve.bootorder"
  string = "nousb"
```

This is a lightweight way to pass configuration from the hypervisor to
the guest firmware without modifying the OVMF binary.

### Persistence

Boot order configuration is persisted in `/persist/vault/appbootconfig/`
and is restored on EVE restart. This ensures that VMs maintain their configured
boot order across EVE reboots, boot order is applied even if LPS is temporarily
unreachable at boot time, and configuration survives power cycles.

## Related Documentation

- [LPS.md](./LPS.md) - Overview of Local Profile Server and all its endpoints
- [BIOS-FIRMWARE.md](./BIOS-FIRMWARE.md) - OVMF firmware configuration and usage
- [eve-api PROFILE.md](https://github.com/lf-edge/eve-api/blob/main/PROFILE.md) - Formal API specification for all LPS endpoints

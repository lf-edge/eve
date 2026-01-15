# VM Boot Order Configuration

This document describes how to configure the boot order for virtual machines (
VMs) running on EVE, with a focus on USB boot priority control.

## Overview

By default, UEFI-based VMs prioritize USB devices in their boot order according
to the UEFI specification. EVE provides runtime control over VM boot order
through three mechanisms:

1. **Controller API**: The `boot_order` field in `VmConfig` allows setting boot
   order as part of the application configuration from the controller.
2. **Local Profile Server (LPS)**: The `/api/v1/appbootinfo` endpoint allows
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

## LPS-Controlled Boot Order

EVE implements per-VM boot order control through the LPS
`/api/v1/appbootinfo` endpoint. This approach provides per-VM granularity
where different VMs can have different boot order settings. Configuration is
managed via LPS which makes it suitable for air-gapped deployments. Settings are
persisted and survive EVE reboots. Changes take effect on the next VM restart.

## How It Works

Boot order configuration flows through EVE's internal components (zedagent →
domainmgr → hypervisor → OVMF firmware). The effective boot order is determined
by merging all configured sources according to the precedence rules.

EVE uses a patched OVMF firmware with `EveBootOrderLib` that reads boot order
configuration via QEMU's fw_cfg mechanism. This approach is necessary because
EVE's USB passthrough uses dynamic hotplug—USB devices are attached to running
VMs at runtime via QMP, and QEMU's standard `bootindex` parameter only works
for devices configured at VM startup.

For detailed internal architecture, see
[pkg/pillar/docs/boot-order-internals.md](../pkg/pillar/docs/boot-order-internals.md).

### Boot Order Values

| Value    | Effect                                                        |
|----------|---------------------------------------------------------------|
| `"usb"`  | USB devices are prioritized in the boot order                 |
| `"nousb"`| USB devices are removed from boot order (disk boots first)   |
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

The `/api/v1/appbootinfo` endpoint is bidirectional: EVE POSTs current boot
status and LPS responds with boot configuration updates. This follows the
standard LPS pattern used by other endpoints like `/api/v1/appinfo`.

### API Endpoint

```http
POST /api/v1/appbootinfo
```

### Request Format (EVE → LPS)

EVE sends the current effective boot order and its source for each application:

```json
{
  "apps_boot_info": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "displayname": "production-vm",
      "boot_order": "BOOT_ORDER_NOUSB",
      "source": "BOOT_ORDER_SOURCE_LPS"
    },
    {
      "id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      "displayname": "deployment-vm",
      "boot_order": "BOOT_ORDER_USB",
      "source": "BOOT_ORDER_SOURCE_CONTROLLER"
    }
  ]
}
```

### Response Format (LPS → EVE)

LPS responds with boot configuration when there are changes to apply:

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

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200  | Config included in response body |
| 204  | No changes needed; preserve current config |
| 404  | Not implemented or no config; clear cached config |

### Field Descriptions

| Field         | Required | Description                                          |
|---------------|----------|------------------------------------------------------|
| `server_token`| Yes      | Must match the token configured in EdgeDevConfig     |
| `id`          | No*      | Application UUID                                     |
| `displayname` | No*      | User-friendly application name                       |
| `usb_boot`    | No       | Boot order enum: `BOOT_ORDER_USB`, `BOOT_ORDER_NOUSB`, or `BOOT_ORDER_UNSPECIFIED` |

*At least one of `id` or `displayname` must be provided.

### Source Values (in request)

| Source | Description |
|--------|-------------|
| `BOOT_ORDER_SOURCE_UNSPECIFIED` | No explicit boot order was configured |
| `BOOT_ORDER_SOURCE_LPS` | Set by LPS via `/api/v1/appbootinfo` |
| `BOOT_ORDER_SOURCE_CONTROLLER` | Set by Controller API via `VmConfig.boot_order` |
| `BOOT_ORDER_SOURCE_DEVICE_PROPERTY` | Set by device property `app.boot.order` |

### LPS Behavior

Each LPS response represents the complete desired state. Applications NOT
included in the response will fall back to the next priority level (Controller
API setting, then Device Property, then firmware default - which means no
fw_cfg is passed to QEMU). Sending the same configuration multiple times has no
effect. Changes take effect on the next VM restart. Configuration is saved to
disk and survives EVE reboots.

**BOOT_ORDER_UNSPECIFIED handling**: When `usb_boot` is set to `BOOT_ORDER_UNSPECIFIED`
(or omitted), it means "no override" - the next priority level is used (Controller
API setting, then Device Property). This allows operators to selectively override
only specific apps via LPS while letting others use their configured values.

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

## When to Use Boot Order Configuration

The primary use case for boot order configuration is when an operator needs to
**install an operating system to a VM from a USB stick**. In this scenario:

1. Attach a bootable USB drive with the OS installer to the device
2. Configure the VM's boot order to `"usb"` to prioritize USB boot
3. Pass through the USB device to the VM
4. Start the VM - it will boot from the USB installer
5. Complete the OS installation to the VM's disk
6. Change boot order back to `"nousb"` or default to boot from disk
7. Restart the VM to boot the newly installed OS

All three mechanisms (Device Property, Controller API, and LPS) provide this
capability:

- Use **Device Property** (`app.boot.order`) to set a device-wide default
- Use **Controller API** (`VmConfig.boot_order`) to configure specific VMs
- Use **LPS** for air-gapped environments where controller connectivity is
  limited

## Related Documentation

- [CONFIG-PROPERTIES.md](./CONFIG-PROPERTIES.md) - Device configuration properties including `app.boot.order`
- [LPS.md](./LPS.md) - Overview of Local Profile Server and all its endpoints
- [BIOS-FIRMWARE.md](./BIOS-FIRMWARE.md) - OVMF firmware configuration and usage
- [eve-api PROFILE.md](https://github.com/lf-edge/eve-api/blob/main/PROFILE.md) - Formal API specification for LPS endpoints
- [pkg/pillar/docs/boot-order-internals.md](../pkg/pillar/docs/boot-order-internals.md) - Internal architecture and concurrency model (for developers)

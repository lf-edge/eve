# Boot Order Configuration: Internal Architecture

This document describes the internal architecture for VM boot order configuration.
For user-facing documentation on how to configure boot order, see
[docs/VM-BOOT-ORDER.md](/docs/VM-BOOT-ORDER.md).

## Overview

Boot order configuration flows from the controller and LPS through zedagent to
the VM firmware. The following diagram shows all components involved:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                          Controller                                     │
│                                                                         │
│  Device Property: app.boot.order = "nousb"  (device-wide default)       │
│  App Config: apps[].fixedresources.boot_order = BOOT_ORDER_USB (per VM) │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
        │
        │ Config delivery
        │
        │       ┌─────────────────────────────────────────────────────────┐
        │       │         Local Profile Server (LPS)                      │
        │       │             (Optional Override)                         │
        │       │                                                         │
        │       │  POST /api/v1/appbootinfo (every 1min)                  │
        │       │    Request: boot status (AppBootInfoList)               │
        │       │    Response: boot config (AppBootConfigList)            │
        │       └─────────────────────────────────────────────────────────┘
        │                          │ ▲
        ▼                          ▼ │
┌─────────────────────────────────────────────────────────────────────────┐
│                              EVE                                        │
│                                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌────────────────────┐         │
│  │  zedagent    │--->│  domainmgr   │--->│ KVM/Xen hypervisor │         │
│  │              │    │              │    │                    │         │
│  │ Merges boot  │    │ Applies boot │    │ Passes boot order  │         │
│  │ order from   │    │ order to VM  │    │ to QEMU via fw_cfg │         │
│  │ all sources  │    │ config       │    │                    │         │
│  └──────────────┘    └──────────────┘    └────────────────────┘         │
│                                                   │                     │
└───────────────────────────────────────────────────│─────────────────────┘
                                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         QEMU (per VM)                                   │
│  fw_cfg: opt/eve.bootorder = "nousb" | "usb" | absent                   │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    OVMF Firmware (per VM)                               │
│  EveBootOrderLib adjusts UEFI boot order based on fw_cfg value          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Firmware Integration

EVE uses a patched version of OVMF (TianoCore EDK2) that includes
`EveBootOrderLib`. This library reads the `opt/eve.bootorder` fw_cfg file from
QEMU during early boot, parses the value (`usb`, `nousb`, or empty), and adjusts
the UEFI boot order accordingly before the boot menu is displayed. The patched
OVMF is built as part of EVE's `pkg/uefi` package.

The boot order is passed to OVMF via QEMU's fw_cfg mechanism:

```ini
[fw_cfg]
  name = "opt/eve.bootorder"
  string = "nousb"
```

This is a lightweight way to pass configuration from the hypervisor to the guest
firmware without modifying the OVMF binary.

## Why Not QEMU bootindex?

QEMU provides a standard `bootindex=N` parameter for setting device boot
priority. We cannot use this mechanism because EVE's USB passthrough for KVM
uses dynamic hotplug via QMP `device_add` at runtime, not static device
configuration.

The `bootindex` parameter is only supported at VM startup time in the config
file or command line—it cannot be specified when adding devices via QMP. When
the usbmanager detects a physical USB device and attaches it to a running VM,
OVMF sees the new device and adds it to the boot order using default UEFI
priority (which favors removable media). Since we cannot control the boot
priority of dynamically-added devices through QEMU, we need the OVMF patch to
manipulate the boot order at firmware level where all devices—both static and
hotplugged—are visible.

## Persistence

Boot order configuration is persisted to survive EVE reboots:

- **LPS boot config**: saved to `/persist/vault/appbootconfig/` on each change
- **Controller boot order**: persisted as part of `AppInstanceConfig`
- **Device property**: persisted as part of `GlobalConfig`

On startup, saved LPS config is loaded from disk into `currentAppBootConfigs`,
then applied when `appBootInfoTask` starts. After that, LPS is polled for
updates via the `/api/v1/appbootinfo` endpoint.

## Polling Intervals

LPS communication (`POST /api/v1/appbootinfo`):

- Normal: every 1 minute
- When LPS returns 404: throttled to every 1 hour
- Posted immediately when boot order changes (controller config, device property)

The endpoint is bidirectional: EVE posts boot status and receives boot config
in response. This follows the standard LPS pattern used by `/api/v1/appinfo`,
`/api/v1/radio`, etc.

## Concurrency Model

Boot order requires merging values from multiple sources (LPS, Controller,
Device Property) into a single `AppInstanceConfig.BootOrder` field. This creates
a synchronization challenge because updates arrive from different goroutines.

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                           zedagent process                              │
│                                                                         │
│  ┌─────────────────────┐     ┌─────────────────────┐                    │
│  │  Main goroutine     │     │  appBootInfoTask    │                    │
│  │  (event loop)       │     │  goroutine          │                    │
│  │                     │     │                     │                    │
│  │  - Controller config│     │  - POSTs to LPS     │                    │
│  │    (parseconfig.go) │     │    every 1 minute   │                    │
│  │  - Device property  │     │  - Updates cache    │                    │
│  │    (app.boot.order) │     │  - Calls apply      │                    │
│  │  - Calls evaluate   │     │    AppBootConfig()  │                    │
│  │    AppBootOrder()   │     │                     │                    │
│  └──────────┬──────────┘     └──────────┬──────────┘                    │
│             │                           │                               │
│             │  Reads from               │  Writes to                    │
│             │  the cache                │  the cache                    │
│             ▼                           ▼                               │
│  ┌──────────────────────────────────────────────────┐                   │
│  │       currentAppBootConfigs (map + mutex)        │                   │
│  │       LPS boot order cache                       │                   │
│  │       Protected by sideController.Mutex          │                   │
│  └──────────────────────────────────────────────────┘                   │
│             │                           │                               │
│             │  Both goroutines read     │                               │
│             │  from cache and write     │                               │
│             │  merged result to AIC     │                               │
│             ▼                           ▼                               │
│  ┌──────────────────────────────────────────────────┐                   │
│  │           AppInstanceConfig (pubsub)             │                   │
│  │           Protected by bootOrderUpdateMx mutex   │                   │
│  └──────────────────────────────────────────────────┘                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

**LPS config arrives** (appBootInfoTask goroutine):

```text
postAppBootInfo()               HTTP POST to LPS, receive config in response
       ↓
processReceivedAppBootConfig()  Update cache (holds sideController.Mutex)
       ↓
applyAppBootConfig()            Merge with other sources
       ↓
evaluateAppBootOrder()          Determine effective boot order
       ↓
Publish to domainmgr            Updated BootOrder in AppInstanceConfig
```

**Controller config arrives** (main goroutine):

```text
parseConfig()                   Receives EdgeDevConfig (holds sideController.Mutex)
       ↓
parseAppInstanceConfig()        Process app configs
       ↓
evaluateAppBootOrder()          Reads LPS cache, merges sources
       ↓
Publish to domainmgr            Updated BootOrder in AppInstanceConfig
```

**Device property changes** (main goroutine):

```text
handleGlobalConfigImpl()        Pubsub handler for GlobalConfig
       ↓
applyDevicePropertyBootOrder()  Called for each app
       ↓
evaluateAppBootOrder()          Reads LPS cache, merges sources
       ↓
Publish to domainmgr            Updated BootOrder in AppInstanceConfig
```

### Synchronization

Two mutexes are used with a strict lock ordering to prevent deadlock:

1. **`sideController.Mutex`** - Protects `currentAppBootConfigs` cache and other
   sideController state. This is the "outer" lock.

2. **`sideController.bootOrderUpdateMx`** - Protects the read-modify-write cycle
   on `AppInstanceConfig`. This is the "inner" lock.

**Lock Ordering Rule**: Always acquire `sideController.Mutex` BEFORE
`bootOrderUpdateMx` to avoid ABBA deadlock.

```go
// In sideController (handleconfig.go):
type sideController struct {
    sync.Mutex                    // Protects currentAppBootConfigs and other state
    currentAppBootConfigs map[string]types.AppBootConfig
    bootOrderUpdateMx     sync.Mutex  // Protects AppInstanceConfig updates
    // ... other fields
}

// Correct usage pattern (e.g., in applyAppBootConfig):
ctx.sideController.Lock()                   // Outer lock first
defer ctx.sideController.Unlock()
ctx.sideController.bootOrderUpdateMx.Lock() // Inner lock second
defer ctx.sideController.bootOrderUpdateMx.Unlock()
// ... read/modify/write AppInstanceConfig
```

**Important**: The `evaluateAppBootOrder()` function reads from
`currentAppBootConfigs` and assumes the caller already holds
`sideController.Mutex`. It does NOT acquire any locks internally.

All functions that modify boot order follow this pattern:

| Function | File | Lock Acquisition |
|----------|------|------------------|
| `parseConfig()` → `parseAppInstanceConfig()` | parseconfig.go | Holds `sideController.Mutex` at top level |
| `applyAppBootConfig()` | localinfo.go | Acquires both locks in order |
| `applyDevicePropertyBootOrder()` | localinfo.go | Acquires both locks in order |
| `processReceivedAppBootConfig()` | localinfo.go | Holds `sideController.Mutex`, releases before calling `applyAppBootConfig()` |

Note: `sideController.Mutex` protects the LPS cache. The `bootOrderUpdateMx`
mutex protects the `AppInstanceConfig` read-modify-write cycle. Both locks must
be held when calling `evaluateAppBootOrder()` and updating `AppInstanceConfig`.

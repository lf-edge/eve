# Evaluation Manager (evalmgr)

The **evalmgr** microservice manages automatic partition evaluation on evaluation hardware platforms. It tests all three partitions (IMGA, IMGB, IMGC) to select the best one based on hardware compatibility, then enables device onboarding.

## Purpose

On evaluation platforms, EVE ships with three identical OS images pre-installed. The evalmgr automatically:

1. Tests each partition for stability and hardware compatibility
2. Collects hardware inventory during each test
3. Selects the best partition based on detected hardware
4. Blocks onboarding until evaluation completes
5. Enables onboarding once the optimal partition is chosen

This ensures the device boots with the most compatible OS configuration before connecting to the controller.

## Platform Detection

Evalmgr detects evaluation platforms using `/etc/eve-platform` markers. On standard platforms (IMGA/IMGB only), it immediately allows onboarding without testing.

## Evaluation Workflow

### Phase 1: Initialization

- Detects current partition (IMGA, IMGB, or IMGC)
- Reconciles failed boots by detecting partitions stuck in "inprogress" state
- Marks failed partitions as bad (priority=0) to prevent future boot attempts
- Publishes initial `EvalStatus` for the onboarding gate

### Phase 2: Stability Testing

- Starts a stability timer (15 minutes) for the current partition
- Collects hardware inventory (lspci, lsusb, dmidecode, etc.)
- Publishes status updates with countdown and progress
- On timeout: marks partition as "good" (priority=2) and schedules next untested partition

### Phase 3: Partition Cycling

- Reboots to next untested partition with highest priority
- GRUB automatically boots the scheduled partition
- After reboot, evalmgr resumes from Phase 1 with new partition
- Repeats until all partitions tested

### Phase 4: Finalization

- Compares hardware inventories from all tested partitions
- Selects best partition based on device detection (CPU, memory, NICs, PCIe devices)
- Marks best partition with priority=3 and successful=1
- Enables onboarding by setting `AllowOnboard=true`

## GPT Partition Management

**IMPORTANT**: Evalmgr uses **extended GPT partition attributes** that differ from standard EVE partition states. The standard `zboot partstate` command (which maps to `active`, `updating`, `inprogress`, `unused`) **does not work correctly** on evaluation platforms because evalmgr uses custom attribute combinations.

### Extended Attribute Encoding

Evalmgr encodes three fields into GPT partition attributes:

- **Priority** (bits 0-3): Boot order preference (0-15)
- **Tries** (bits 4-7): Remaining boot attempts (0-15)
- **Successful** (bit 8): Boot completion flag (0-1)

Standard EVE only uses these predefined combinations:

- `active` (0x102): priority=2, tries=0, successful=1
- `updating` (0x13): priority=3, tries=1, successful=0
- `inprogress` (0x3): priority=3, tries=0, successful=0
- `unused` (0x0): priority=0, tries=0, successful=0

Evalmgr uses **custom combinations** for evaluation workflow:

| State | Attributes | Priority | Tries | Successful | Meaning |
|-------|------------|----------|-------|------------|---------|
| Scheduled | 0x013 | 3 | 1 | 0 | Ready for first boot |
| Inprogress | 0x003 | 3 | 0 | 0 | GRUB booted it, not confirmed |
| Good | 0x102 | 2 | 0 | 1 | Tested and stable |
| Best | 0x103 | 3 | 0 | 1 | **Selected as optimal** |
| Bad | 0x000 | 0 | 0 | 0 | Failed, never boot |

Note the `Best` state (0x103) with priority=3 and successful=1 - this combination is **not used by standard EVE** and will display as `UNKNOWN` in `zboot partstate` output.

GRUB reads priorities and automatically boots the highest priority partition. The evalmgr manipulates these attributes to orchestrate the evaluation sequence.

### Debugging Extended Attributes

To decode partition attributes on evaluation platforms, use `zboot partstate` with the `-d` flag:

```bash
# Standard output (may show UNKNOWN for evaluation states)
zboot partstate IMGA

# Decoded output showing priority/tries/successful breakdown
zboot partstate IMGA -d
```

Example output:

```text
UNKNOWN 0x103 decoded:
  Priority: 3
  Tries left: 0
  Successful: 1
```

The `-d` flag uses the same bit field extraction formulas as evalmgr's `gpt_access_cgpt.go`.

## Hardware Inventory Collection

During each partition test, evalmgr collects detailed hardware information:

- **lspci**: PCI device enumeration
- **lsusb**: USB device enumeration
- **dmidecode**: System BIOS/firmware details
- **dmesg**: Kernel boot messages
- **iommu-groups**: IOMMU group mappings
- **spec.sh**: Structured JSON hardware specification

Inventory is stored in `/persist/eval/<partition>-<timestamp>/` for comparison and debugging.

## Onboarding Gate

The `client` microservice subscribes to `EvalStatus` published by evalmgr:

- **Evaluation platforms**: blocks onboarding until `AllowOnboard=true`
- **Standard platforms**: allows immediate onboarding
- **Manual override**: `/persist/eval/allow_onboard` file bypasses the gate

This prevents premature controller connection during hardware testing.

## State Persistence

Evalmgr maintains two types of state:

### Source of Truth: GPT Attributes

- Algorithm reads partition states from GPT via partition manager
- Boot decisions made by GRUB reading GPT priorities
- Survives power loss and unexpected reboots

### Audit Trail: /persist/eval/state.json

- Human-readable JSON with timestamps and notes
- Records evaluation progress and best slot selection
- Not used for control flow or algorithm decisions
- Provides debugging and troubleshooting information

This design ensures GPT and algorithm state never diverge.

## Scheduler State Machine

```text
Idle → StabilityWait → Scheduled → Finalized
  ↑                         ↓
  └─────────────────────────┘
        (next partition)
```

- **Idle**: No active evaluation
- **StabilityWait**: Testing current partition stability
- **Scheduled**: Next partition scheduled, reboot imminent
- **Finalized**: All partitions tested, best selected

## Reboot Analysis

On each boot, evalmgr analyzes the previous reboot reason:

- **Planned**: Expected reboot (evaluation-next-slot, evaluation-finalize)
- **Unplanned**: Unexpected reboot (panic, watchdog, power loss)
- **First boot**: No previous reboot reason found

This helps classify partition stability and detect boot failures.

## Configuration

Evalmgr uses configurable timers (primarily for testing):

- **Stability period**: 15 minutes per partition
- **Status updates**: Every 25 seconds
- **Reboot countdown**: 10 seconds before reboot
- **Watchdog**: 40 second warning, 3 minute error

## Testing

Evalmgr includes comprehensive test infrastructure:

- Mock partition manager with in-memory GPT simulation
- Mock system reset that simulates reboots without actual system calls
- Mock filesystem (afero) for state persistence testing
- Full evaluation flow tests covering all phases
- GRUB bootloader behavior simulation

Tests verify partition cycling, failure detection, inventory collection, and best partition selection.

## Debugging

To check evaluation status:

```bash
# View current evaluation status
cat /persist/eval/state.json

# Check partition attributes with extended decode (evaluation platforms)
zboot partstate IMGA -d
zboot partstate IMGB -d
zboot partstate IMGC -d

# View hardware inventory
ls -la /persist/eval/

# Manual override to allow onboarding
echo "1" > /persist/eval/allow_onboard
```

**Note**: On evaluation platforms, `zboot partstate` may show `UNKNOWN` states. Use the `-d` flag to decode the extended attribute fields (priority, tries, successful) used by evalmgr.

The `check-eval-state.sh` script provides automated status checking.

## Integration Points

- **client.go**: Subscribes to EvalStatus for onboarding gate
- **zboot**: Provides partition attribute manipulation
- **GRUB**: Reads GPT priorities to determine boot order
- **debug container**: Provides inventory collection scripts
- **diag**: Displays evaluation status in diagnostics output

## Related Components

- **types.EvalStatus**: Published status structure
- **types.EvalPersist**: Persistent state structure
- **utils.IsEvaluationPlatform()**: Platform detection
- **cmd/zboot**: GPT partition management tool

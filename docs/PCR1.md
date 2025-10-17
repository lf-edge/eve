# PCR 1 Exclusion: Security Impact

PCR 1 is designated in the TCG Platform Firmware Profile (PFP) specification
for recording Host Platform Configuration. This index is designed to
measure configuration data associated with code measured into PCR 0.

Specifically, PCR 1 captures OEM configuration data such as SMBIOS tables,
setup variables, and policy configurations. It may also include measurements
of elements hash of applied CPU Microcode updates.

The rationale for excluding PCR 1 from a sealing policy is based on minimizing
brittleness. The items measured into PCR 1 are typically the volatile elements
of the platform's initial configuration. If routine configuration data changes
(even non-security critical ones) occur, the PCR value will change.

For clarity, the following events can be measured into PCR 1, contributing to
its volatile nature.

## Mandatory Measurements

1. CPU Microcode Updates: If Platform Firmware loads a CPU microcode update,
it MUST be measured, typically using the event type EV_CPU_MICROCODE.

2. UEFI Boot Variables: The EFI Boot#### and UEFI BootOrder variables MUST
be measured, using the event type EV_EFI_VARIABLE_BOOT2.

3. Configuration Flags: If the platform permits configuration options for
optional PCR measurements, it MUST measure which measurements are currently
enabled or disabled using the event type EV_PLATFORM_CONFIG_FLAGS. Toggling
these options will always change the PCR value.

## Recommended Measurements (SHOULD/MAY be measured)

1. SMBIOS Tables: SMBIOS tables are considered OEM configuration data and go
into PCR 1.

2. UEFI Setup Variables/CMOS Data: Security-related configuration data from
non-volatile storage, such as UEFI setup variables or CMOS, may be measured.
EFI Setup Variables containing security-relevant configuration data (not
measured elsewhere) SHOULD be measured using EV_PLATFORM_CONFIG_FLAGS or
EV_EFI_VARIABLE_DRIVER_CONFIG. Security-relevant CMOS data and platform NVRAM
data SHOULD be measured using EV_EFI_HANDOFF_TABLES2 (excluding sensitive data
like passwords).

3. Hardware Device List: The hardware device list (e.g., PCI devices, onboard
video adapters) SHOULD be measured using EV_TABLE_OF_DEVICES.

4. Non-Host Configuration: Configuration for a Non-Host Platform (e.g., Intel
Management Engine) that can only be updated by Platform Firmware SHOULD be
measured using EV_NONHOST_CONFIG.

5. OEM Setup Utility Entry: The action "Entering ROM Based Setup" SHOULD be
measured with EV_ACTION if the utility is OEM-provided and does not require
an unconditional reset.

6. ESCD/Other Handoff Tables: ESCD and other tables MAY be measured using
EV_EFI_HANDOFF_TABLES2.

7. SPDM Configuration: Firmware configuration of embedded componentssupporting
SPDM "GET_MEASUREMENTS" SHOULD be measured using EV_EFI_SPDM_FIRMWARE_CONFIG.

8. Non-Boot Security Policy: If the security configuration policy is NOT boot
security sensitive, it goes into PCR

## Conclusion

By excluding PCR 1, the sealing policy avoids sensitivity to mutable
configuration settings, maintaining utility while focusing on verifying less
volatile aspects of the boot chain.
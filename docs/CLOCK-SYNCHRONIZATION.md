# Clock Synchronization

The Operating System might use different sources and devices to measure
time. For instance, on a bare metal scenario, the OS can program a hardware
timer to generate interrupts on a precise frequency, so it's easy to know
how much time have passed between interrupts. Factors like temperature and
voltage fluctuations might cause some interference leading to a clock
drift, but usually it can take months (or even years) to observe seconds of
drift on systems without any external clock synchronization. On virtualized
systems, however, hardware timers are virtualized by the hypervisor, which
cannot ensure the precision guaranteed by physical hardware devices.

The common and best practice to keep clocks synchronized, for both
virtualized and non-virtualized systems, is to use the [NTP protocol](./DEVICE-CONNECTIVITY.md#network-time-protocol-ntp),
so clocks are precisely synchronized with external servers equipped with high
precision devices, like GPS or Atomic clocks.

EVE always tries to keep its clock synchronized by embedding a NTP Client
that synchronizes the system's clock since the boot time. It's recommended
to all Edge Applications (containers or regular VMs) to also run a NTP
client in order to keep their clocks synchronized.

## Clock sources

The Linux kernel can use different sources to measure time: hardware
timers, counters or even paravirtualized drivers. On x86 platforms, most
common clock sources available are:

- tsc: Time Stamp Counter, a counter that basically is incremented on each
  CPU clock cycle. The TSC can vary between platforms and implementations.
  Some can change frequency while the processor is in power saving state or
  is completely turned off. Some are stable and never stop to count, even
  while the processor is sleeping. Even though this counter is stable, its
  exact frequency is many times not specified, so it requires the kernel to
  execute a calibration process during initialization. Other available
  timers can be used in the calibration process. Some processors already
  specify the TSC frequency through the CPUID instruction, which will not
  require calibration.

- acpi_pm: Corresponds to a reliable hardware timer counter defined by
  the ACPI standard. This counter has a frequency fixed clock at 3.58MHz.

- HPET: It's a High Precision Event Timer, very precise, still slower to
  read compared to TSC.

- kvm-clock: The kvm-clock is a paravirtual driver for KVM (so it's
  available on guest virtual machines), the host shares information about
  its clock with guests.

## Virtual PTP 1588 clock (PTP_KVM) support

PTP stands for Precision Time Protocol, an IEE standard (IEEE 1588-2019)
that defines a protocol for high precision clock synchronization throughout
a computer network. PTP hardware devices are usually present in network
cards, so they can be used to generate timestamps for many network
protocols. EVE supports a virtual PTP clock (for x86_64) that can be
exposed to guests as a hardware PTP device able to synchronize Guest's
clock with host's (EVE) clock. A client program, such as the chrony daemon,
is required in order to synchronize the system's clock with the virtual PTP
device.

## Recommendations when NTP is not available on the Guests

For some use cases, like when devices are running on very remote locations,
network connectivity might not be available all the time, so NTP
synchronization can be compromised, or some times, completely unavailable.
In order to keep Guest's clock synchronized with Host's clock and avoid
clock drifts when NTP is not available, one of the following options are
recommended:

- Use the virtual PTP kvm clock. EVE enables the chrony daemon
  automatically for containers when the environment variable
  EVE_ENABLE_CHRONY=1 is defined. This variable can be setup for each Edge
  Application through the remote controller. For regulars VMs, the chrony
  daemon must be installed and configured to sync the guest's clock with
  the device /dev/ptp0 or /dev/ptp_kvm. The kernel must also support the
  virtual PTP device driver.

- Use acpi_pm as a reliable clock source. The parameter
  "clocksource=acpi_pm" must be added to the bootloader options from the
  VM.

- Some hardware platforms have known issues related to the TSC counter,
  such as report wrong frequencies, present some instability or get the
  counter reset by BIOS while in some power save mode, for example. Many of
  these known issues are fixed by Linux kernel or by an updated processor's
  microcode. It's important to check if the current hardware platform has
  any known issue regarding TSC. In such a case, another timer source (such
  as HPET or acpi_pm) can be used as a clocksource. The corresponding
  kernel command line on GRUB's configuration can be set to change the
  default clocksource. It's also recommended to check possible fixes and
  updates in the BIOS provided by the vendor.

## References

- [https://www.vmware.com/pdf/vmware_timekeeping.pdf](https://www.vmware.com/pdf/vmware_timekeeping.pdf)

- [https://www.kernel.org/doc/Documentation/virtual/kvm/timekeeping.txt](https://www.kernel.org/doc/Documentation/virtual/kvm/timekeeping.txt)

- [https://www.kernel.org/doc/Documentation/timers/timekeeping.txt](https://www.kernel.org/doc/Documentation/timers/timekeeping.txt)

- [https://support.ntp.org/Support/KnownOsIssues#Section_9.2.2.](https://support.ntp.org/Support/KnownOsIssues#Section_9.2.2.)

- [https://kb.vmware.com/s/article/1006427](https://kb.vmware.com/s/article/1006427)

- [https://www.redhat.com/en/blog/avoiding-clock-drift-vms](https://www.redhat.com/en/blog/avoiding-clock-drift-vms)

- [https://standards.ieee.org/ieee/1588/6825/](https://standards.ieee.org/ieee/1588/6825/)

- [https://opensource.com/article/18/12/manage-ntp-chrony](https://opensource.com/article/18/12/manage-ntp-chrony)

# Hardware Security Recommendation

## TPM

TPM plays a key role in providing security in EVE, from the measured boot and device health attestation to storing cryptographic keys. To achieve **EVE's minimum hardware security requirement** make sure the Edge device is equipped with a TPM chip that supports at least TPM 2.0 standard with SHA256 banks available for use.

When using a TPM, is important to consult your manufacturer and make sure the selected TPM is not vulnerable to [CVE-2018-6622](https://nvd.nist.gov/vuln/detail/CVE-2018-6622). The vulnerability arises from an ambiguity in TPM 2.0 specification in handling S3 sleep (suspend to RAM). During the S3 sleep, power is cut off from most of the system, including the TPM chip, which results in a reset of PCR values. A TPM firmware is vulnerable if not implementing PCR save/restore to NVRAM at S3 mode, in this case a compromised system can put the system in S3 sleep mode and on wake up extend the PCR values to arbitrary fake (but valid) values, passing the remote attestation stage. Please beware that disabling S3 sleep in UEFI might not be sufficient because a attacker with physical access might be able to re-enable it, running the system with a patched TPM firmware is the most secure way.

## Memory

EVE is capable of running virtual machines and containers provided by the user. The code executed from the user-provided application or VMs can not be fully trusted, as such hosting hardware should use memory that contains mitigations against [Rowhammer](https://www.wikiwand.com/en/Row_hammer) style attacks.

To prevent [Cold boot](https://www.wikiwand.com/en/Cold_boot_attack) style of attacks, a hardware encryption module capable of transparently encrypting the content of the memory is required since most of the software-based mitigations are easy to circumvent. For example, you can leverage Total Memory Encryption (TME) technology introduced in Intel's Willow Cove microarchitecture.

## Boot Security Technologies

EVE is leveraging TPM for remote attestation and secret sealing, but it relies on the fact that parts of the boot process that is out of the scope of EVE security, are not malicious and can't lie about the measurements.

Attacks like ROM swapping or SPI flash reprogramming can completely break the chain of trust TPM is relying on. To prevent this type of attacks using Chassis Intrusion Detection or enabling technologies like [Intel® Hardware Shield](https://www.intel.com/content/www/us/en/architecture-and-technology/hardware-shield-vpro-platform-security-paper.html) can be helpful, for example, Intel® Boot Guard in Measured Boot mode can measures the initial boot block (IBB) into TPM before the CPU runs the IBB.

## BIOS and UEFI Security

Correctly securing the BIOS and UEFI is another crucial step in reducing the possible attacks from outside of EVE. A malicious code injected into BIOS could modify the SMI handlers to create SMM rootkit. This would give the malware unrestricted access to physical memory and peripherals connected to the host machine, beside that a BIOS malware can survive operating system update/replacement and disk drive wipe or replacement.

So it is necessary for system BIOS to include a protected small core block of firmware that executes first and is capable of verifying the integrity of other firmware components, including Option Roms.

A malicious system BIOS installation might be initiated by a user, an exploit in the system BIOS itself, or from an organization update server. To prevent malicious BIOS installation, the BIOS update mechanisms must include a process for verifying the authenticity and integrity of BIOS updates. This can be achieved by employing a form of authentication, for example using digital signatures and a protected Root of Trust for Update (RTU) that contains a signature verification algorithm and a key store that includes the public key needed to verify the signature on the BIOS update image. In addition RTU must be the only entity that is able to unlock the flash and, when unlocked, only the RTU should have the ability to write to the BIOS flash memory.

The authenticated BIOS update by itself is not enough, for example, a malicious actor can rollback to an authentic but vulnerable system BIOS to exploit a vulnerability to gain permanent system access. It is necessary for the BIOS update process to employ a rollback protection mechanism in addition to the authenticated updates.

In some systems, there might be a secure local update mechanism that allows the installation of BIOS images without using the authenticated update. This mechanism is usually reserved for recovering from a corrupted system BIOS. But to reduce the risk of abuse by a malicious actor, make sure the process is protected at least by a password. Please be aware that a physical lock (e.g., a motherboard jumper) **might not suffice**, becurse Edge devices are usually deployed in the field and an attackers can have physical access to the device.

Lastly it is important to lockdown the BIOS/UEFI configuration using a strong password.

 For more detailed information, please read NIST's BIOS Protection Guidelines [[800-147](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-147.pdf), [800-147B](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-147b.pdf)] and for UEFI check out NSA's [UEFI Defensive Practices Guidance](https://www.nsa.gov/portals/75/documents/what-we-do/cybersecurity/professional-resources/ctr-uefi-defensive-practices-guidance.pdf), in particular *"Table 1: Recommended Settings"*.

## Device Firmware

Make sure the firmware's authenticity and integrity are checked before execution and during update. Update the firmwares to the latest available version and make sure the implementation has mechanisms like rollback protection in place to prevent flashing an older vulnerable version to the system (see "BIOS and UEFI Security" for more details). Updating firmwares via [UEFI capsules](https://github.com/fwupd/fwupd) it is considered and will be supported by EVE.

It is also important to ask the OEM for a clear support lifetime, this includes the BIOS/UEFI, TPM firmware, and any other chip on the system. Publicized vulnerabilities can hurt a fully functional system that is passed its support lifetime.

## Intel Hyperthreading

If maximum performance is not critical, it is recommended to disable Hyperthreading if the system is handling sensitive information. This technology has a reputation for being flawed and paving the road for side-channel attacks and information disclosures.

## Supply Chain

There is always risk of compromising the device in supply chain, although detecting backdoor'ed circuit is hard, there are technologies available that can help ensuring the authenticity and integrity of hardware. This technologies are mostly limited to firmware and its configuration, for example Intel provides Intel® Transparent Supply Chain ("ITSC") to enable component level traceability, In addition, technologies like Intel® Platform Firmware Resilience ("IPFR") provides protect-in-transit feature, allowing customers to lock and unlock systems to guard against firmware changes during shipment.

## Other

Other recommendations include protecting or removing debugging interfaces, disabling [known backdoors](https://bios-pw.org/) and more. For a more comprehensive list check out [Hardware Security Verification Requirements](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS/blob/master/en/V5-Hardware_Platform_Requirements.md#security-verification-requirements) from OWASP ISVS and [Hardware Design weaknesses](https://cwe.mitre.org/data/definitions/1194.html) by CWE.

# VTPM

*(if you're looking for old VTPM documents, please refer to [PTPM](docs/PTPM.md))*

Virtual TPM container integrates SWTPM with QEMU, in order to emulate a full Virtual TPM 2.0 (1.2 not supported) for running VMs and bare-metal containser. It create a SWTPM instance per VM. The SWTPM instance is configured to use a Unix Domain Socket as a communication line, by passing the socket path to the QEMU virtual TPM configuration, QEMU automatically creates a virtual TPM device for the VM which is accessible like a normal TPM under `/dev/tpm*`.

VTPM configures SWTPM to saves and loads the encrypted TPM state on/from the `/persist/swtpm/tpm-state-[VM-UUID]`, so at the next VM boot all the TPM keys, TPM NVRAM data, etc are present in the virtual TPM. SWTPM is configured to encrypt each VM/Containers virtual TPM state data using a 256-bit AES key, this key is stored in the hardware TPM with a PCR policy (measured boot) and is accsiable to EVE only. Please note that if a hardware TPM is not avaibale to EVE, the virtual TPM state is stored unencrypted.

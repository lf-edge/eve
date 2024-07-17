# VTPM

*(if you're looking for old VTPM documents, please refer to [PTPM](docs/PTPM.md))*

Virtual TPM container integrates SWTPM with QEMU, in order to emulate a full Virtual TPM for running VMs and bare-metal containser. It create a SWTPM instance per VM. The SWTPM instance is configured to use a Unix Domain Socket as a communication line, by passing the socket path to the QEMU virtual TPM configuration, QEMU automatically creates a virtual TPM device for the VM which is accessible like a normal TPM under `/dev/tpm*`.

VTPM configures SWTPM to saves and loads the TPM state on/from the disk, so at the next VM boot all the TPM keys, TPM NVRAM data, etc are present in the virtual TPM. In addition SWTPM is configured to encrypt each VM/Containers virtual TPM state data using a 256-bit AES key.

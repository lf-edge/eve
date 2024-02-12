# EVE Volume Key Recovery Tool

This is tool made to conveniently extract [EVE](https://github.com/lf-edge/eve/) volume encryption key from TPM. It can extract keys both in plain text format and in an encrypted format suited for inserting into a cloud controller database like [Adam](https://github.com/lf-edge/adam) or [Zedcloud](https://zededa.com/). Note the that tool can only extract keys from TPM if the device state (current PCR values) match the original state where key was seald.

## Usage

The tool compiles for Alpine environment (EVE's base). The [recover-tpm.sh](pkg/debug/scripts/recover-tpm.sh) downloads the arch specific binary and comes with predefined values to extract keys from specific versions of EVE, but the main tool is flexiable in its usage:

```text
$ ./recovertpm --help
Usage of ./recovertpm:
  -cert-index uint
        Device key (aka device cert) index
  -cert-path string
        Path to the device cert file
  -check-cert
        Compare the device cert from vault with the device cert inside TPM
  -ecdh-index uint
        ECDH key index
  -export-cloud
        Export the vault key in cloud encrypted form
  -export-plain
        Export the vault key in plain text
  -import-encrypted
        Import the vault key in encrypted form
  -import-plain
        Import the vault key in plain text
  -input string
        Input file for the vault key
  -log string
        log file path
  -output string
        Output file for the vault key
  -pcr-hash string
        PCR Hash algorithm (sha1, sha256) (default "sha1")
  -pcr-index string
        PCR Indexes to use for sealing and unsealing (default "0")
  -priv-index uint
        Vault Key private key NVRAM index
  -pub-index uint
        Vault key public key NVRAM index
  -reseal
        Reseal the vault key under new PCR indexes and hash algorithm
  -srk-index uint
        Storage Root Key (SRK) index
  -tpm-pass string
        TPM device password (if needed)
  -tpm-path string
        Path to the TPM device (character device) (default "/dev/tpm0")
```

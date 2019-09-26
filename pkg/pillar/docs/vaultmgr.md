# Vault Manager Microservice

Vault Manager is responsible for providing data security at rest on EVE.
For more details refer to [https://github.com/lfedge/eve/blob/master/docs/SECURITY.md
](https://github.com/lf-edge/eve/blob/master/docs/SECURITY.md)[https://wiki.lfedge.org/display/EVE/Encrypting+Sensitive+Information+at+Rest+at+the+Edge](https://wiki.lfedge.org/display/EVE/Encrypting+Sensitive+Information+at+Rest+at+the+Edge)


## Vault

A "Vault" refers to a directory, where files under that directory are stored in encrypted format on the disk.


## Default Vaults

By default, vaultmgr creates two vaults on the EVE node: `persist/img` and `/persist/config`. They are created when an EVE device is booting for the first time, after an USB installation.


## Encryption Tool

EVE uses `fscrypt`, an open source tool to encrypt files using native file system capability of Linux Kernel. For more details, please refer to [https://github.com/google/fscrypt](https://github.com/google/fscrypt)


## Vault Keys

The encryption key is randomly generated during first time installation, and stored inside TPM.  This encryption key is used to encrypt/unlock the Vaults.


## Troubleshooting

`/persist/IMGX/log/vaultmgr.log` has logs from vaultmgr. One can also use `/opt/zededa/bin/fscrypt` command to print the status of vaults on the pillar shell prompt.


## Future Work

There is a lot of scope for further hardening of data security at rest, at the Edge. Please refer to [https://wiki.lfedge.org/display/EVE/Security+APIs](https://wiki.lfedge.org/display/EVE/Security+APIs) for future enhancements being discussed.

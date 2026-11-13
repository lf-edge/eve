# go-tpm2

[![Tests](https://github.com/canonical/go-tpm2/workflows/Tests/badge.svg)](https://github.com/canonical/go-tpm2/actions?query=workflow%3ATests) [![GoDoc](https://godoc.org/github.com/canonical/go-tpm2?status.svg)](https://godoc.org/github.com/canonical/go-tpm2)

This repository contains a go library for interacting with TPM 2.0 devices. Some currently supported features are:

 - All authorization modes: cleartext password, HMAC session based and policy session based.
 - All session configurations: salted or unsalted + bound or unbound.
 - Session-based command and response parameter encryption using AES-CFB or XOR obfuscation.
 - Session-based command auditing.
 - Backends for Linux TPM character devices and TPM simulators implementing the Microsoft TPM 2.0 simulator interface.
 
The current support status for each command group is detailed below.
 
 Command group | Support | Comment
 --- | --- | ---
 Start-up | Full |
 Testing | Full |
 Session Commands | Full |
 Object Commands | Full |
 Duplication Commands | Partial | TPM2_Duplicate and TPM2_Import are supported
 Asymmetric Primitives | None |
 Symmetric Primitives | None |
 Random Number Generator | Full |
 Hash/HMAC/Event Sequences | Full |
 Attestation Commands | Full |
 Ephemeral EC Keys | None |
 Signing and Signature Verification | Full |
 Command Audit | Full |
 Integrity Collection (PCR) | Partial | TPM2_PCR_Extend, TPM2_PCR_Event, TPM2_PCR_Read and TPM2_PCR_Reset are supported
 Enhanced Authorization (EA) Commands | Partial | All commands are supported except for TPM2_PolicyLocality, TPM2_PolicyPhysicalPresence, TPM2_PolicyTemplate and TPM2_PolicyAuthorizeNV
 Hierarchy Commands | Partial | TPM2_CreatePrimary, TPM2_HierarchyControl, TPM2_Clear, TPM2_ClearControl and TPM2_HierarchyChangeAuth are supported
 Dictionary Attack Functions | Full |
 Miscellaneous Management Functions | None |
 Field Upgrade | None |
 Context Management | Full |
 Clocks and Timers | Partial | TPM2_ReadClock is supported
 Capability Commands | Full |
 Non-Volatile Storage | Partial | All commands are supported except for TPM2_NV_Certify
 Vendor Specific | None |
  
 ## Relevant links
  - [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
  - [IBM's Software TPM 2.0](https://sourceforge.net/projects/ibmswtpm2/)

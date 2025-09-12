# VComLink: Asynchronous Communication Channel for Host-VM Interaction

## Overview

VComLink is a communication agent that facilitates asynchronous communication between a host and virtual machines (VMs) through the use of the vsock protocol. The primary goal of VComLink is to provide a simple and efficient mechanism for sending and receiving requests between the host and VMs. For simplicity, VComLink processes one request per read/write operation.

## VSOCK Communication

VComLink utilizes vsock, a communication protocol designed specifically for VM-host interactions. The vsock communication channel operates on a unique port `2000`. This port enables the guest VM to establish a connection with the host.

## TPM Service Protobuf API

This section describes the Protocol Buffer (protobuf) message definitions used for TPM operations. Definitions use `proto3` syntax

### Messages

#### TpmRequestGetPub

Request to retrieve the public part of a TPM key.

| Field | Type | Description |
| - | - | - |
| index | uint32 | TPM index of the key to get |

#### TpmResponseGetPub

Response containing the public part of a TPM key.

| Field | Type | Description |
| - | - | - |
| public | bytes | Public part of the key in TPM wire format |
| algorithm | uint32 | Algorithm used in the key as a TPM_ALG_ID value |
| attributes | uint32 | Bitmask of key attributes |

#### TpmRequestSign

Request to sign data using a TPM key.

| Field | Type | Description |
| - | - | - |
| index | uint32 | TPM index of the signing key |
| data | bytes | Data to be signed |

#### TpmResponseSign

Response containing the generated signature.

| Field | Type | Description |
| - | - | - |
| algorithm | string | Signing algorithm used |
| rsa_signature | bytes | RSA signature (if applicable) |
| rsa_hash | string | Hash algorithm used with RSA |
| ecc_signature_r | bytes | ECC signature R component |
| ecc_signature_s | bytes | ECC signature S component |
| ecc_hash | string | Hash algorithm used with ECC |

#### TpmRequestReadNv

Request to read from a TPM non-volatile (NV) index.

| Field | Type | Description |
| - | - | - |
| index | uint32 | TPM NV index to read |

#### TpmResponseReadNv

Response containing data read from a TPM NV index.

| Field | Type | Description |
| - | - | - |
| data | bytes | Data read from the NV index |

#### TpmRequestActivateCredParams

Request to get parameters for activating a TPM credential.

| Field | Type | Description |
| - | - | - |
| index | uint32 | TPM index of the signing key (must be restricted signing key, for example AIK) |

#### TpmResponseActivateCredParams

Response with EK and AIK parameters needed for credential activation.

| Field | Type | Description |
| - | - | - |
| ek | bytes | Public part of the Endorsement Key (EK) |
| aik_pub | bytes | Public part of the Attestation Identity Key (AIK) |
| aik_name | bytes | Name of the AIK in TPM wire format |

#### TpmRequestGeneratedCred

Request to submit a credential and secret for activation.

| Field | Type | Description |
| - | - | - |
| cred | bytes | Credential to be activated |
| secret | bytes | Encrypted secret to be decrypted |
| aik_index | uint32 | Index of the Attestation Key (AIK) |

#### TpmResponseActivatedCred

Response containing the decrypted secret.

| Field | Type | Description |
| - | - | - |
| secret | bytes | Decrypted secret from the activated credential |

#### TpmRequestCertify

Request to certify a key using AK.

| Field | Type | Description |
| - | - | - |
| index | uint32 | Index is the TPM nv index of the key to certify |

#### TpmResponseCertify

Response to TpmRequestCertify, containing attestation data and signature.

| Field | Type | Description |
| - | - | - |
| public | bytes | Public is the public part of the certified key, in TPM wire format. |
| sig | bytes | Sig is the signature of the attestation payload, in TPM wire format. |
| attest | bytes | Attest is the attestation data, in TPM wire format. |

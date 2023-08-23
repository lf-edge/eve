/*
Package tpm2 implements an API for communicating with TPM 2.0 devices.

This documentation refers to TPM commands and types that are described in
more detail in the [TPM 2.0 Library Specification]. Knowledge of this
specification is assumed in this documentation.

Communication with Linux TPM character devices and TPM simulators
implementing the Microsoft TPM2 simulator interface is supported.

The core type by which consumers of this package communicate with a TPM is
[TPMContext].

[TPM 2.0 Library Specification]: https://trustedcomputinggroup.org/resource/tpm-library-specification/
*/
package tpm2

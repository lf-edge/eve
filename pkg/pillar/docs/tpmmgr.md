
# TPM Manager(tpmmgr) microservice

This service is responsible for managing the Trusted Platform Module on EVE systems

## What is Trusted Platform Module

Trusted Platform Module is a purpose-build hardware module, for providing tools to
build a secure and trusted endpoint. It can securely create crypto keys, seal secrets,
and help measure various components of the system and store the measurements in a
tamper-proof manner. For more details, refer to <https://trustedcomputinggroup.org> which is
the govering body for defining specifications for TPM implementations.

## Role of tpmmgr

Role of tpmmgr is to help interface with Trusted Platform Modules from Edge Virtualization Engine,
to make the edge device secure. To begin with, one of the goals is to secure the device identity
certificate by generating its ECDSA private key in TPM. More details at the LF Edge Wiki page here:
<https://wiki.lfedge.org/display/EVE/Device+Identity%2C+Onboarding%2C+Security+Foundation>
<https://wiki.lfedge.org/display/EVE/Device+Identity+rooted+at+TPM>

## The TSS2.0 support

tpmmgr uses go-tpm package from Google, to interface with the TPM device, which implements TSS2.0.
Go-tpm package is hosted at <https://github.com/google/go-tpm/>. Go-tpm is licensed under Apache License 2.0.

## Debugging

To print TPM vendor information, use `/opt/zededa/bin/tpmmgr printCapability`
To see logs from tpmmgr, one can find it under `/persist/<IMGA/IMGB>/log/tpmmgr.log`

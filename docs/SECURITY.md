# EVE Security Overview

## Reporting security issues

EVE community takes security seriously. If you discover a security issue, please bring it to our attention right away!

Please DO NOT file a public issue, instead send your report privately to eve-security@lists.lfedge.org.

## Introduction

What makes EVE a secure-by-design system is that it has been developed from the ground up with security in mind. EVE doesn't rely on 3rd party or add-on components to provide trust in the system, but rather offers a set of well-defined principles on which a trust model can be built. You will notice that EVE doesn't call itself a trusted system -- but rather a trustworthy one. The distinction is subtle, but very important and was first articulated by [Joanna Rutkowska](https://www.darkreading.com/vulnerabilities---threats/rutkowska-trust-makes-us-vulnerable/d/d-id/1330587). Joanna, of course, is the architect of [Qubes OS](https://www.qubes-os.org) with which EVE shares a good deal of core security principles like [security by compartmentalization](https://www.qubes-os.org/doc/glossary/#qubes-os) and focusing on representing all user applications as VM-based abstractions. In EVE, the same VM-based approach to defining applications is built around [Edge Containers specification](ECOS.md).

We have made an effort to provide users of EVE with a system that is both practically secure and can be deployed in a zero-touch fashion. In order to achieve our goals we put forward a few guiding principles (some of them borrowed from Chromium's approach to securing mobile devices):

* Provide strong, industry standard (such as [X.509](https://en.wikipedia.org/wiki/X.509)) cryptographic identity for Edge Nodes and software entities alike
* Make Edge Nodes secure-by-default
* Defense in depth (based on the hypervisor boundary protection guarantees)
* Relying on state-of-the-art hardware elements (such as TPM and TEE) for providing robust root-of-trust and secure key management
* Remote attestation and measured boot
* Robust trust model between EVE and its controller
* Workloads which are immutable
* Secure overlay network

In the rest of this document, we explain these principles and discuss some expected use cases for Edge Node devices running EVE.  We then give a high-level overview of the threat model against which we will endeavor to protect our users, while still enabling them to make full use of their cloud-based controller orchestration service.

## EVE deployment model

Reasoning about security and trustworthiness of any system is only meaningful if one understands how the system is going to be deployed and used. EVE main deployment targets are Edge Nodes. Typically, Edge Nodes are small form factor, ruggedized PC-like systems that are deployed in physically insecure environments with ad-hoc networking without any firewall-like guarantees. This type of environment is very similar to the one assumed by mobile computing systems (laptops, tablets and smart phones) and it is not a coincidence that EVE shares a lot of security principles with operating systems developed for mobile computing. For example, EVE's approach to thwarting physical attacks and protecting the integrity of the software stack running on the Edge Node may look similar to if you're familiar with Chromium OS.

There is, however, one crucial difference between mobile computing environment and Edge and that is the notion of who controls the system. With mobile there's always a human being end user who has direct physical access to the hardware running mobile computing operating system, in EVE's case that entity is a remote, cloud-based controller. Any security related event that originates on EVE's side (e.g. measurements coming from boot sequence) has to be reliably passed and acknowledged by the controller and any action that is triggered on the Edge Node by EVE (e.g. storage key rotation) has to be scheduled by the controller.

In short, EVE's deployment model forces us to protect against an opportunistic adversary with full physical access to and Edge Node and Edge Node's networks through a combination of system hardening, defense in depth, process isolation, secure autoupdate, measured boot, encryption, and seamless integration with EVE's controller security policies.

## Security capabilities vs. security policies

At the end of the day, EVE only does what its controller instructs it to do. This puts an enormous premium on protecting the trust between EVE instance and its controller at all costs (in both direction) but it also allows us to have a clear division of responsibilities between the two:

* EVE only implements security capabilities, never security policies
* Controller orchestrates EVE's security capabilities in order to realize sophisticated policies

On EVE's side, this separation allows us to focus on a small number of well designed capabilities (AKA security building blocks) that are guaranteed to have a well defined interactions between each other. For example, while EVE may provide a capability for storing encrypted binary blobs on the Edge Nodes it will be up to the controller's security policy to determine which pieces of data will be stored there.

Controller and its management of security policies are out of scope for this document.

## EVE threat model

Just as Chromium, we consider two different kinds of adversaries:

* An opportunistic adversary
* A dedicated adversary

The opportunistic adversary is just trying to compromise an individual Edge Node and/or data.  They are not targeting a specific user or enterprise, and they are not going to steal, disassemble or modify the Edge Node but they are very likely to have prolonged physical access to it. This level of physical access allows an opportunistic adversary a chance to replace trusted network and I/O connections with those of their own making, though. Unlike Chromium, we assume that this will facilitate things like DNS or other network-level attacks and will place them within an opportunistic adversary's reach.

The dedicated adversary may target a user or an enterprise specifically for attack.  They are willing to steal Edge Nodes to recover data or account credentials (not just to re-sell the device to make money). They are also willing and capable of modifying an Edge Node with extra hardware and software components. They may also do anything that the opportunistic adversary can do.

The EVE contributors and community need to prioritize which security risks to focus on and in which order. For now, we are focusing mainly on risks posed by opportunistic adversaries. As the project matures and the community grows, we will increase our scope to include dedicated adversaries and other security considerations.

## Establishing trust between EVE and EVE's controller

### EVE trusting its controller

Recall that EVE's deployment model presupposes a controller that can exercise arbitrary control over Edge Nodes. EVE provides the following capabilities that can protect against an adversary trying to take control over an Edge Node by pretending to be a controller:

* The controller's network address (hostname and port) is considered immutable and can only be changed by a total reinstall of EVE
* The controller's identity is verified by a Root CA which is also considered immutable and sealed in TPM where possible. This is used in the TLS verification for API V1 and in the object signature verification in API V2
* The TLS identity of the controller is verified by a Root CA. This is a single Root CA in API V1 and a larger set of root CAs plus the ability to express trust in proxy certificates in API V2.

The principle that EVE's node forever gets bound to a fixed controller may strike some as too restrictive, but it allows a much easier reasoning about security properties and, since controller gets identified by the DNS name still allows a certain flexibility in deployment. It does, however, stand in stark contrast to EVE's fundamental guarantee of never ever requiring a "truck roll" to manage software on Edge Nodes. Unfortunately, avoiding a "truck roll" in this particular case will require us to design a comprehensive asset transfer protocol that tackles a whole host of thorny problems like:

* guaranteeing that at the completion of the asset transfer the Edge Node always ends up in a "pristine state" (so that the previous owner of the Edge Node doesn't accidentally leak something to the next one)
* providing a way for the next owner to validate the hardware of the Edge Node (so that no additional components or firmware outside of the visibility of the TPM attestation can be implanted by the previous owner)

Given the complexity of designing such a protocol for EVE (especially solving the hardware validation problem), we are currently punting on the problem and declaring software-based asset transfer out of scope for now. However, we are in no way suggesting that this should be a permanent state of affairs.

If there's an attempted modification of either controller's address (stored in /config/server) and controller's Root CA (/config/root-certificate.pem) Edge Node should get disconnected from the controller and should be forced to do a hardware-assisted clear operation and start all over again.

On systems where TPM is available, the idea is to change TPM authentication policy from password to HMAC based authentication (TPM2_PolicyAuthValue), with hash calculated from the Root CA.  When device key is created, HMAC from Root CA will be passed, which is to be honored for every TPM command related to the key entity. i.e Each time Sign command is passed to TPM, the Root CA hash needs to be the same. If someone changes Root CA, HMAC will not match, and the device will be disconnected from the controller, forcing the user to do a TPM clear and start all over again.

### EVE trusting side-channel configuration

The use of [object signing](../api/OBJECT-SIGNING.md) is designed to enable delivering device configuration using side channels such as USB sticks. But the details of timestamp checks to avoid replay attacks has yet to be designed and implemented. Those aspects are [TBD](https://github.com/lf-edge/eve/issues/233)

### Identity of EVE's instance

Each device running EVE has a unique device certificate. Further, if the device has a TPM, the device private key is generated and stored in the TPM to prevent cloning the device identity.

If the device does not have a TPM/TEE for secure key generation and storage then the device certificate and private key are stored in a file in the /config partition, hence the confidentiality of the private key depends on the physical protection of the storage on the device.

The device certificates are currently self-signed by the device with a long lifetime, since instead of certificate revocation for untrusted devices the controller can explicitly mark them as untrustworthy (the device certificate is only used to communicate to the controller).

But in the future EVE can send Certificate Signing Requests over the EVE API to have the controller ask some backend CA to sign the device certificates in the cases where that facilitates managing the devices.

The device generates additional key pairs and certificates, since different keys are required to have different usage. This includes an ECDH certificate used for object encryption (to minimize exposure of secrets in the configuration) which is generated using the TPM is available, and stored in a file in the /persist partition. There is also an attestation certificate  (with the appropriate key usage settings to perform remote attestation from the TPM), and a certificate for the TPM endorsement key (which is needed by some vTPM use). All three additional certificates are signed using the device private key. Collectively we call these additional device-side certificates EdgeNode certificates.

### Controller trusting EVE

As a result of on-boarding a device, the controller is told to trust the device with a particular device certificate (and also that it is "owned" by some particular user of the controller).

Separately measured boot with remote attestation will ensure that the device is running the expected versions and hashes of firmware and of the EVE software. On successful attestation, Controller provides a particular one-time token (called integrity-token), which needs to be produced by EVE for a successful configuration request. Controller will reject incoming configuration requests, if the integrity-token does not match the expected value, and will reply with HTTP error code 403, to force EVE to re-attest and generate a new integrity-token. EVE stores this token in memory, and hence is valid only for the current boot session. This ensures that every boot session automatically triggers a fresh attestation cycle, thereby measuring and validating the software components all over again.

#### Initial on-boarding

There are several ways in which devices running EVE can be on-boarded to a controller. The details depend on the support available in the location, e.g., a factory, where the EVE software is installed on the device.

One approach is that EVE is booted and the TPM is used to generate the device certificate, and that device certificate is securely delivered from the factory to the intended end user of the device. That end user can then upload the device certificate to the controller to claim the device. (A controller would presumably check for attempts for more than one party claiming ownership of the same device hence so that a disclosed device certificate can be detected.)

Another approach is that an onboarding token (in the form of a certificate and private key) is added to the EVE image, but the factory does not need to boot EVE and upload information after installing the image. When the device boots EVE the first time at the installation site it will present the onboarding certificate and its hardware serial numbers using a register API call to the controller, and the user can scan and upload the serial number to the controller. This has weaker security especially if serial numbers can be guessed by an attacker having an account on the same controller, but different devices can be given different onboarding tokens to make such attacks more difficult.

The onboarding token lives in conf/onboard.*.pem in the repo, and this is used to build the config disk image which ends up in /config/ when EVE is booted. Thus the onboarding key UUID can be extracted using

```shell
openssl x509 -in conf/onboard.cert.pem -text | grep CN
```

The [generate-onboard.sh](../pkg/pillar/scripts/generate-onboard.sh) script can be used to generate such onboarding certificates.

A variant of that approach is to use a random soft serial number. When EVE is installed it generates a /config/soft_serial which is a random 128-bit UUID. If installed from a USB stick this serial number (together with the less random hardware serial number) are written to a directory on the USB installer stick.

When EVE is calling the register API it will present both the hardware serial and soft serial, hence if the controller has been told of the random soft serial for the device we avoid depending on guessable hardware serial numbers.

In both cases of calling the register API the factory can choose the granularity of the onboarding token. A single onboarding token can be used for a large production run of devices, or for fewer devices, or even be generated for each individual device. The choice depends on the capabilities of the factory installation site and the logistics of conveying the information (device certificate, onboarding tokens and/or serial numbers) from the factory to the end user.

## Encrypted Data Store

EVE provides a security capability to enable storing sensitive information on the built-in storage of the Edge Node where EVE is running, while providing reasonable protections from this information leaking outside of the running EVE instance. Note that this is not an end-to-end encryption solution, but rather a capability that mitigates some of the attack vectors based on physical possession of the Edge Node. The data itself, while protected in-flight by the transport level security mechanism such as TLS, is expected to be un-encrypted before it lands on the Edge Node.

One big driving factor for this is protecting Edge Containers and the Data Volumes they utilize. We expect a high number of Edge Containers deployed by EVE's users to receive and process business sensitive information from sensors and the Cloud.  Data collected and processed by these Edge Containers is stored in their virtual storage, which is backed by the hardware storage on the EVE platform. It is important that even if the storage drive or entire device is stolen, the data remains secure.  For this reason, data should be in encrypted form when it is stored.

See [Encrypting Sensitive Information at Rest at the Edge](https://wiki.lfedge.org/display/EVE/Encrypting+Sensitive+Information+at+Rest+at+the+Edge) design specification.

The storage encryption _location_ is in `/persist/vault/`, and encompasses application content and volumes.

The storage encryption _mechanism_ uses standard filesystem encryption, fscrypt for the ext4 file system and native ZFS encryption for the ZFS file system.

This storage encryption _key_ is symmetric and generated solely on the edge device using a TPM, and then sealed into TPM using PCR values. This means that
the key can only be retrieved from TPM when the firmware and software booting sequence has not changed. The encryption key is not written to disk storage,
and must be retrieved on each boot from the TPM, which is available only if the PCR values are identical, i.e. the boot chain is unchanged.

When a system upgrades, by definition the boot process changes, leading to different values in the PCRs. and the TPM will not be able to unseal the encryption key.
To handle this scenario, the "encrypted backup key" mechanism is used. This mechanism is similar to Network-Based Disk Encryption (NBDE) and Shamir Secret Sharing. It
requires participation of both parties, controller and device, to use the backup key.

1. When the vault encryption key is generated, in addition to sealing the key to PCRs, it also is encrypted using regular TPM encryption, i.e. not sealed to PCR values. Because it is encrypted using the TPM, but not stored in the TPM, it is not available on the device by itself either.
1. The encrypted copy of the key is sent to the controller. Because it is encrypted using the TPM, the controller cannot read the key either. At this point, neither controller nor device by itself can read the backup key.
1. When the system upgrades, the controller validates via remote attestation that the new PCR values are acceptable, and then sends the encrypted key to the device.
1. The device decrypts the key using the TPM. It now has a valid vault decryption key, which it seals to the new PCR values.

To decrypt the key, one has to be on the same device with access to the same TPM, and the firmware+software on that device has to pass the
[remote attestation](https://wiki.lfedge.org/display/EVE/Measured+Boot+and+Remote+Attestation) check in the controller.

## Secure Overlay Network

EVE provides a secure overlay network for ECOS for cases when east-west communication is needed between ECOS. This is built using [LISP](https://tools.ietf.org/html/rfc6830) with a strong security foundation. Each ECO is attached to a mesh network instance which describes common parameters for the overlay network such as the location of the LISP RTR.

Each ECO has a unique certificate and private key generated when the ECO is deployed, and the LISP endpoint identifier contains a hash of that public key. This enables secure authenticated registrations with the LISP map server since the device can prove that it owns the private key whose hash is in the EID as part of the LISP register message.

Two ECOs communicating using the overlay will get an secure channel since LISP will perform a key exchange using the pair of public keys (which are bound to the EIDs per above).

In addition, the LISP map server can provide ability to limit access to the mappings for certain EIDs based on the EID which is trying to look them up.

## Details on keys and certificates

These details are specified in [KEYS-AND-CERTS](KEYS-AND-CERTS.md).

## Hardware Security

These details are specified in [Hardware Security Recommendation](SECURITY-HARDWARE.md).

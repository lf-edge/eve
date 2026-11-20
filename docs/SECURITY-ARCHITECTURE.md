# EVE Security Overview

## Introduction

What makes EVE a secure-by-design system is that it has been developed from the ground up with security in mind. EVE doesn't rely on 3rd party or add-on components to provide trust in the system, but rather offers a set of well-defined principles on which a trust model can be built. You will notice that EVE doesn't call itself a trusted system -- but rather a trustworthy one. The distinction is subtle, but very important and was first articulated by [Joanna Rutkowska](https://www.darkreading.com/vulnerabilities---threats/rutkowska-trust-makes-us-vulnerable/d/d-id/1330587). Joanna, of course, is the architect of [Qubes OS](https://www.qubes-os.org) with which EVE shares a good deal of core security principles like [security by compartmentalization](https://www.qubes-os.org/doc/glossary/#qubes-os) and focusing on representing all user applications as VM-based abstractions. In EVE, the same VM-based approach to defining applications is built around [Edge Containers specification](ECOS.md). That VM-based default has deliberate exceptions, described in [Isolation between applications and EVE](#isolation-between-applications-and-eve).

We have made an effort to provide users of EVE with a system that is both practically secure and can be deployed in a zero-touch fashion. In order to achieve our goals we put forward a few guiding principles (some of them borrowed from Chromium's approach to securing mobile devices):

* Provide strong, industry standard (such as [X.509](https://en.wikipedia.org/wiki/X.509)) cryptographic identity for Edge Nodes and software entities alike
* Make Edge Nodes secure-by-default
* Defense in depth (based on the hypervisor boundary protection guarantees)
* Relying on state-of-the-art hardware elements (such as TPM and TEE) for providing robust root-of-trust and secure key management
* Remote attestation and measured boot
* Robust trust model between EVE and its controller
* Workloads which are immutable

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

The opportunistic adversary is just trying to compromise an individual Edge Node and/or data.  They are not targeting a specific user or enterprise, but they are very likely to have prolonged physical access to the Edge Node, and they may steal it or its storage drive and read or copy the drive offline. They are not going to disassemble the Edge Node or modify its hardware. This level of physical access also allows an opportunistic adversary a chance to replace trusted network and I/O connections with those of their own making. Unlike Chromium, we assume that this will facilitate things like DNS or other network-level attacks and will place them within an opportunistic adversary's reach.

The dedicated adversary may target a user or an enterprise specifically for attack.  They are willing and capable of modifying an Edge Node with extra hardware and software components. They may also do anything that the opportunistic adversary can do.

Theft of an Edge Node or its drive is addressed in [Encrypted Application and User Storage](#encrypted-application-and-user-storage); [What a stolen or copied disk reveals](#what-a-stolen-or-copied-disk-reveals) summarizes the result.

## Scope and platform assumption

Devices originally installed with EVE 5.10.4 (released August 2020) or earlier are out of scope. Those releases stored the vault key unsealed in TPM non-volatile storage, and an upgrade keeps that copy and continues to use the same key.

The rest of this document assumes that the device has a TPM 2.0 that supports ECC P-256 (ECDSA and ECDH), RSA-2048, AES-128-CFB and an active SHA-256 PCR bank, and that EVE created its device, ECDH and quote keys in that TPM at first boot. Everything this document says about device identity, attestation and encryption at rest depends on such a TPM.

### Platforms without such a TPM

EVE also runs on devices without a usable TPM -- no TPM, a TPM 1.x, or a TPM 2.0 that fails EVE's runtime checks -- so that such devices can still onboard and run applications ([tpmmgr](../pkg/pillar/docs/tpmmgr.md)). On those devices:

* The device identity key and the ECDH and quote keys are generated in software and stored in files: the device key in the CONFIG partition and the ECDH key under `/persist/certs`. The confidentiality of these keys, and therefore of the device identity and of object-encrypted secrets, depends on the physical protection of the device's storage.
* No endorsement key certificate is published and no attestation quotes are produced.
* The vault is created unencrypted, and the device reports encryption at rest as disabled ([vault](../pkg/pillar/docs/vault.md)). No vault key is escrowed with the controller.
* Nothing is measured into PCRs, so changes to the CONFIG partition, including the controller address and root certificate, are not detected.

On a TPM 2.0 that does not support AES-128-CFB, EVE seals and unseals the vault key with a plain PCR policy session, without the parameter encryption described in [Sealing the vault key to the boot state](#sealing-the-vault-key-to-the-boot-state), so the key crosses the CPU-to-TPM bus in cleartext ([evetpm](../pkg/pillar/evetpm/evetpm.md)).

## Establishing trust between EVE and its controller

### EVE trusting its controller

Recall that EVE's deployment model presupposes a controller that can exercise arbitrary control over Edge Nodes. EVE provides the following capabilities that can protect against an adversary trying to take control over an Edge Node by pretending to be a controller.

All communication between EVE and its controller is outbound-only HTTPS using mutual TLS:

* **TLS minimum version**: TLS 1.2
* **Cipher suites**: `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
* **Client certificate**: TPM-resident ECDSA P-256 device key
* **Server validation**: the controller's TLS certificate is validated against Mozilla's CA certificate bundle, which the Alpine Linux `ca-certificates` package installs in the read-only EVE root filesystem, against `/config/root-certificate.pem`, and against any proxy CA certificates configured for the device. Object signatures ([Object signing](#object-signing)) are validated against `/config/root-certificate.pem` alone, which is immutable after installation: it is stored in the read-only CONFIG partition and measured into PCR 14. Releases before EVE 16.13.0, and before 16.0.2 on the 16.0 LTS branch, validate TLS against `/config/v2tlsbaseroot-certificates.pem`, installed with the device, instead of the Mozilla bundle.
* **Controller address**: the controller's network address (hostname and port, `/config/server`) cannot be changed by the controller itself, by an application, or over any network path. The one interface that can change it is the [local TUI](LOCAL-TUI.md), which renders only on a physically attached monitor and offers the operation only before the device is onboarded.

Both `/config/server` and `/config/root-certificate.pem` live in the CONFIG partition, which is measured into PCR 14 file by file ([What PCR 14 covers](#what-pcr-14-covers)). Any change is detected at the next boot, and since PCR 14 is part of the vault key access control policy, the key no longer unseals and `/persist/vault` stays unavailable until the controller accepts the new measurements and releases the [encrypted backup key](#encrypted-backup-key).

EVE can be configured to trust an enterprise transparent or explicit proxy's CA, so that TLS termination at a corporate proxy does not break connectivity. This motivates the next two layers.

The principle that EVE's node forever gets bound to a fixed controller may strike some as too restrictive, but it allows a much easier reasoning about security properties and, since controller gets identified by the DNS name still allows a certain flexibility in deployment. It does, however, stand in stark contrast to EVE's fundamental guarantee of never ever requiring a "truck roll" to manage software on Edge Nodes. Unfortunately, avoiding a "truck roll" in this particular case will require us to design a comprehensive asset transfer protocol that tackles a whole host of thorny problems like:

* guaranteeing that at the completion of the asset transfer the Edge Node always ends up in a "pristine state" (so that the previous owner of the Edge Node doesn't accidentally leak something to the next one)
* providing a way for the next owner to validate the hardware of the Edge Node (so that no additional components or firmware outside of the visibility of the TPM attestation can be implanted by the previous owner)

Given the complexity of designing such a protocol for EVE (especially solving the hardware validation problem), we are currently punting on the problem and declaring software-based asset transfer out of scope for now. However, we are in no way suggesting that this should be a permanent state of affairs.

### Object signing

Above TLS, all controller-to-device configuration messages are signed by the controller ([object signing](https://github.com/lf-edge/eve-api/tree/main/OBJECT-SIGNING.md)). Signature verification uses the controller's signing certificate, which chains to `/config/root-certificate.pem`. This prevents a content-inspecting TLS-terminating proxy from modifying configuration in transit even if it can read the TLS plaintext.

* Signing uses ECDSA; the device fetches the controller's signing certificates from the controller
* The device verifies the signature before acting on any configuration
* A configuration older than the one already applied is rejected by its `config_timestamp`, whatever channel delivered it

Object signing is also what makes it safe to deliver configuration over side channels such as USB sticks, as the [bootstrap configuration](CONFIG.md#bootstrap-configuration) (`/config/bootstrap-config.pb`) does. A bootstrap configuration is in addition applied only once, since EVE records its SHA-256 hash.

### Object-level encryption

A third layer protects secrets within the configuration (datastore credentials, WiFi passwords, cloud-init user data, app environment variables) from being readable by a proxy or by EVE microservices that don't need them ([object level encryption](OBJECT-LEVEL-ENCRYPTION.md)):

* The shared encryption key is derived via ECDH (P-256) between the device's TPM-resident ECDH key pair and the controller's ECDH certificate. The device's ECDH key is not itself an encryption key: it is used only for this key agreement, which yields the symmetric key that encrypts the content
* The shared secret is fed through a SHA-256 KDF per NIST SP 800-56A Rev. 3 / FIPS 180-4
* The resulting key is used as AES-256 in CFB mode with a controller-provided initialization vector
* The controller's ECDH certificate can be rotated at any time, which rotates the derived key
* Decrypted secrets are kept only in memory within the microservice that needs them (downloader for datastore credentials, nim for WiFi keys, domainmgr for cloud-init user data), never written to persistent storage in plaintext
* These protections apply when the controller sends the fields encrypted. The EVE API also accepts each of them in cleartext; encrypting them is the controller's responsibility

The complete transit protection stack is therefore TLS, then object signing, then object encryption, each layer covering an additional threat: a network attacker, a proxy in the middle, and a microservice that has no need for the secret.

### Outbound-only communication

EVE opens no inbound listening application ports on management interfaces by default. All controller communication is EVE-initiated polling (configuration fetch, and log and metric upload). The controller cannot push to the device; it can only respond to polls.

On EVE-k ([EVE-K.md](EVE-K.md)), Kubernetes cluster formation and management requires ports 6443/tcp (k3s API server), 10250/tcp (kubelet), 2379-2380/tcp (etcd), 12346/tcp (cluster-status server) and 8472/udp (flannel VXLAN) to be open, so EVE admits them implicitly, on the cluster interface only. The cluster-status server on 12346 accepts only TLS 1.3 with a bearer token; each node derives the token and the server's self-signed certificate from the cluster join token with HKDF-SHA256. When the Authorized Cluster Endpoint is enabled, 6443 is also admitted on every interface. The VXLAN overlay carries pod-to-pod traffic unencrypted and unauthenticated, so the cluster network must be trusted.

### Disabling Remote Access

EVE provides a mechanism to build an image with remote access (EdgeView and SSH) disabled, by the presence of `/config/remote_access_disabled`; this can be done by configuring EVE when building an installer. Enabling remote access back requires access to the controller to enable console keyboard access on the edge node, plus physical access to the edge node to issue the `eve remote-access` command. Changing the remote access status from its initial value modifies PCR 14 ([MEASURED-CONFIG](MEASURED-CONFIG.md)), so the vault key no longer unseals until the controller accepts the new measurements. When `remote_access_disabled` is absent -- the default -- SSH and EdgeView are enabled and disabled dynamically by the controller over the EVE API, and those changes do not affect PCR 14. Check the [config document](CONFIG.md#eve-configuration) for more information.

### SSH

SSH is an optional debug console, disabled by default in hardened builds. When enabled:

* `/config/authorized_keys` holds SSH public keys for pre-onboarding access only. It is read at boot solely as a fallback when `/config/GlobalConfig` is absent; once the controller's global configuration is present it is ignored, and the keys actually installed -- and whether port 22 is reachable at all -- follow `debug.enable.ssh` ([CONFIG-PROPERTIES](CONFIG-PROPERTIES.md)), which defaults to empty
* Accepted format: `keytype base64-key comment`; no SSH options are allowed, preventing forced-command or port-forwarding tricks
* No password authentication

### EdgeView

EdgeView is a system container providing on-demand remote troubleshooting access ([EdgeView](../pkg/edgeview/README.md)). Unlike SSH, it is controller-mediated, and every command it runs is logged.

Access is activated by the controller delivering a JWT token in the device configuration. The token specifies a dispatcher endpoint, device UUID, expiration time, an HMAC nonce, and the authentication type. The JWT is time-limited, so sessions expire automatically. The dispatcher is a WebSocket Secure (WSS) relay, so a session never involves direct inbound connectivity to the device.

The authentication types are mutually exclusive and set by the controller:

| Type | Mechanism |
|------|-----------|
| Controller certificate | Every EdgeView command payload is signed by the controller's private signing key and verified on-device using the controller's public certificate. Commands can only originate from the controller. |
| SSH keys | Remote users authenticate with SSH RSA key pairs. Public keys are configured via the ConfigItem `edgeview.authen.publickey`. Any change to this ConfigItem immediately terminates all active EdgeView sessions. |

The EdgeView container mounts all volumes read-only, except `/run/edgeview` and `/persist/tmp`.

Every command received by EdgeView is logged with the client IP address and port, the command and all its parameters, and the username (the public key comment field for SSH key authentication). Log entries are tagged `log-to-event` so the controller can promote them to device events or alerts.

### Controller trusting EVE

As a result of on-boarding a device, the controller is told to trust the device with a particular device certificate (and also that it is "owned" by some particular user of the controller); see [Onboarding](#onboarding).

Separately, measured boot with remote attestation ensures that the device is running the expected versions and hashes of firmware and of the EVE software:

* The device requests a nonce from the controller (replay protection)
* The device generates a TPM quote signing PCR values 0-15 with a TPM-resident quote key
* The controller must accept the quoted PCR values. In most deployments the expected values are pre-accepted in the controller, for the whole fleet or for a single device; otherwise an operator accepts them after the device reports them. How acceptance is configured is up to the controller. This is the mechanism by which a user authorizes changes such as EVE software updates, BIOS updates, or changes to BIOS settings and boot options
* Acceptance of the quoted PCR values completes remote attestation; only then does the controller issue a one-time token, called the integrity-token, which EVE holds in memory for that boot session only
* EVE must present this token in every configuration request. The controller rejects a request whose token does not match with HTTP error code 403, forcing EVE to re-attest
* The controller does not release the [encrypted backup key](#encrypted-backup-key) unless it has accepted the new PCR values, so vault access cannot be restored after a software or firmware change unless the controller accepts it

Every boot session therefore triggers a fresh attestation cycle, and any change to the firmware and software stack must be accepted by the controller, in advance or by an operator after the fact, before the device regains full functionality.

## Encrypted Application and User Storage

EVE provides a security capability to enable storing sensitive information on the built-in storage of the Edge Node where EVE is running, while providing reasonable protections from this information leaking outside of the running EVE instance. Note that this is not an end-to-end encryption solution, but rather a capability that mitigates some of the attack vectors based on physical possession of the Edge Node. The data itself, while protected in-flight by the transport level security mechanism such as TLS, is expected to be un-encrypted before it lands on the Edge Node.

One big driving factor for this is protecting Edge Containers and the Data Volumes they utilize. We expect a high number of Edge Containers deployed by EVE's users to receive and process business sensitive information from sensors and the Cloud.  Data collected and processed by these Edge Containers is stored in their virtual storage, which is backed by the hardware storage on the EVE platform. It is important that even if the storage drive or entire device is stolen, the data remains secure.  For this reason, data should be in encrypted form when it is stored.

See [Encrypting Sensitive Information at Rest at the Edge](https://wiki.lfedge.org/display/EVE/Encrypting+Sensitive+Information+at+Rest+at+the+Edge) design specification.

### The vault

All application content and volumes -- VM images, container images and data volumes -- are stored under `/persist/vault/`. That directory is encrypted using standard filesystem encryption:

* **ext4**: `fscrypt` directory-level encryption, policy v2: AES-256-XTS for file contents, AES-256-CTS for file names
* **ZFS**: native ZFS encryption, `aes-256-gcm`

The vault key is a 256-bit symmetric key generated entirely on-device by the TPM and never written to disk. On devices originally installed with an EVE release before 7.10.0, the vault keeps the key it was created with, whose effective length is 128 bits rather than 256; everything else this document says about the vault key applies to them unchanged.

Each application's virtual TPM state is encrypted by `swtpm` with AES-256-CBC under a per-instance key sealed in the hardware TPM.

Only the vault is encrypted. Device and application logs under `/persist/newlog` ([Logging and time](#logging-and-time)), the state EVE's microservices publish to `/persist/status`, and the CONFIG partition, whose contents are protected by measurement rather than encryption, are all outside it. Keeping the logs outside the vault is also what makes them readable on a device whose vault will not unseal -- the state in which they are most wanted.

### Sealing the vault key to the boot state

The vault key is sealed into the TPM using Platform Configuration Registers (PCRs), which accumulate measurements of every component in the boot chain (firmware, bootloader, kernel, configuration). The TPM releases the key only if the PCR values at unseal time match those at seal time. The key is not written to disk storage and must be retrieved from the TPM on each boot.

The default PCRs are 0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13 and 14, covering UEFI firmware, boot code, boot configuration, and the EVE software stack.

A stolen or cloned disk therefore cannot be decrypted on another machine (different TPM), nor on the same machine with a modified firmware or software stack (different PCR values).

The vault key travels over the physical bus that connects the CPU to the TPM (typically LPC or SPI), and that bus can be passively monitored with inexpensive hardware. EVE therefore protects seal and unseal operations with salted HMAC sessions and AES-128-CFB parameter encryption:

1. Before sealing or unsealing the vault key, EVE opens a TPM2 HMAC session bound to the RSA-2048 Endorsement Key (EK). A random session salt is generated and RSA-OAEP encrypted with the EK public key, so only that TPM can recover it.
1. The session key derived from that salt is used to AES-128-CFB encrypt the key material in the TPM command (seal) and response (unseal).
1. The session also provides an HMAC over each command.

### Flexible PCR policy

The set of PCRs used for sealing is not hardcoded. The controller can instruct a device to adopt a different PCR set. When a new policy arrives, EVE validates it against the device's capabilities, unseals the vault key using the old PCR policy, reseals it using the new PCR set, and reports the updated sealing PCRs (stored in `/persist/status/sealingpcrs`). This allows security administrators to tighten or loosen the binding of the encrypted data to the platform state without physical access or reinstall.

### Encrypted backup key

When the boot chain changes (firmware update, OS upgrade, PCR policy change), the new PCR values differ from those used to seal the key, so the TPM refuses to unseal it. EVE handles this through a two-party backup key mechanism similar to Network-Based Disk Encryption (NBDE) or Shamir Secret Sharing:

1. When the vault key is generated, in addition to sealing it to PCRs, EVE encrypts it using the TPM without binding to PCR values, and sends the encrypted copy to the controller. Because it is encrypted using the TPM, the controller cannot read the key either; neither party can read the backup alone.
1. After a change, the controller sends the encrypted key back to the device only once remote attestation ([Controller trusting EVE](#controller-trusting-eve)) confirms that the controller has accepted the new PCR values.
1. The device decrypts the key using the TPM and reseals it to the new PCR values.

The backup key is only decryptable on the original device (same TPM) and only after that device passes the [remote attestation](https://wiki.lfedge.org/display/EVE/Measured+Boot+and+Remote+Attestation) check in the controller, so the mechanism is not a bypass of the PCR sealing. When the controller is unreachable, the vault key remains sealed to the previous PCR values and the device cannot unseal it on its own.

Note what this means for a device pointed at a different controller, which an on-site operator can do from the [local TUI](LOCAL-TUI.md) before the device is onboarded. Accepting the attestation quote is not the step that unlocks the vault; returning the encrypted backup key is. That key was escrowed with the controller the device was talking to when the key was created, and no other controller has a copy, so a controller that a device has been redirected to cannot unlock the existing vault however readily it accepts the new PCR values.

### What PCR 14 covers

PCR 14 is extended by a measurement pass over the CONFIG partition, file by file, rather than by a single partition hash. Seven files that legitimately differ per device or change during normal operation are excluded from content measurement, but their presence or absence is still measured. [MEASURED-CONFIG](MEASURED-CONFIG.md) lists them and describes the event log the controller uses to report which file changed.

Every file in `/config` that is not on the exclusion list is covered, including `/config/server`, `/config/root-certificate.pem` and `/config/remote_access_disabled`. Any local edit to the controller address, the network override, the global configuration or the authorized keys is detected at the next boot: the vault does not unseal until the controller accepts the new measurements.

### Destroying the vault without reading it

Two paths destroy the vault's contents without disclosing them:

* **Clearing the TPM.** The TPM's lockout authorization is empty and clearing is not disabled, so code running as root on the device can clear the TPM. That erases the sealed vault key and the device's identity keys, and the escrowed backup key can no longer be decrypted either. The vault is lost and the device gets a new identity.
* **An empty key from the controller, before the device holds content.** If the controller returns an empty backup key, EVE removes and recreates the vault empty and reports the unlock method as recreated. That path is gated on the presence of `/persist/status/allow-vault-clean`, which is created when `/persist` is first initialized and removed as soon as the device has something to lose -- the first volume or content it stores, or the first successful escrow of a key. A controller that a device was redirected to before onboarding can therefore wipe a freshly installed device, but not one in service.

### Identity of EVE's instance

Each device running EVE has a unique device certificate. The device private key is generated and stored in the TPM to prevent cloning the device identity.

The device certificates are self-signed by the device with a long lifetime, since instead of certificate revocation for untrusted devices the controller can explicitly mark them as untrustworthy (the device certificate is only used to communicate to the controller). In the future EVE can send Certificate Signing Requests over the EVE API to have the controller ask some backend CA to sign the device certificates in the cases where that facilitates managing the devices.

The device generates additional key pairs and certificates, since different keys are required to have different usage: an ECDH certificate used for object encryption, an attestation certificate, and a certificate for the TPM endorsement key (which is needed by some vTPM use). All three are signed using the device private key. Collectively we call these additional device-side certificates EdgeNode certificates.

| Key/Cert | Algorithm | Purpose | Location |
|----------|-----------|---------|----------|
| Device key | ECC P-256 (ECDSA) | mTLS client authentication, proves device identity | TPM resident (never extractable) |
| Device cert | ECC P-256 | Self-signed by the device key, long-lived | `/config/device.cert.pem` |
| ECDH key | ECC P-256 | Key agreement with the controller's ECDH certificate, deriving the symmetric key for object encryption | TPM resident |
| Quote key | ECC P-256 | Sign TPM PCR quotes | TPM resident (handle `0x81000004`) |
| Endorsement Key (EK) | RSA-2048 | Salts the seal/unseal sessions | TPM resident (handle `0x81000001`) |
| Storage Root Key (SRK) | RSA-2048 | Parent for TPM objects | TPM resident (handle `0x81000002`) |
| Attestation Key (AK) | RSA-2048 | vTPM credential activation | TPM resident (handle `0x81000003`) |
| Vault encryption key | 256-bit symmetric | Unlock `/persist/vault/` | Sealed to TPM PCRs; never on disk |
| Vault backup key | 256-bit symmetric | Recovery after a boot chain change | TPM-encrypted blob at the controller |
| Onboarding key | ECC P-256 | One-time device registration | `/config/onboard.key.pem` |

[KEYS-AND-CERTS](KEYS-AND-CERTS.md) has the details on keys and certificates.

## Software provenance and change control

### The base OS image

The EVE root filesystem -- hypervisor, host kernel and all EVE microservices -- is a single immutable, read-only squashfs image occupying one of two partitions. It is never modified in place and never patched piecewise; it is replaced whole or not at all.

Updates use the two partitions plus GRUB priority boot:

1. The controller names the image in the device configuration. Until the controller activates it, EVE downloads and verifies the image and stops there.
1. On activation EVE writes the image to the unused partition, flips the boot priority and reboots. A power failure during the write leaves the running partition untouched.
1. The new version is on probation for 10 minutes. EVE requires that the device can reach the controller and that no agent crashes or hangs during that window before committing to it.
1. If the probation fails, EVE falls back to the previous partition automatically and reports the failure. It also remembers the failure: if the controller keeps asking for that version, the device refuses to try it again rather than entering a reboot loop.

Progress and outcome are reported to the controller, including the update stage and either the download percentage or the time remaining in the probation window.

A failed update, a bad kernel, a broken NIC driver or a hung agent all converge on the same outcome: the device returns to a known-good software state without a site visit.

### Application images

Application images are named in the device configuration by their SHA-256 digest. EVE downloads the bytes, hashes them, and compares against that digest before the image becomes usable; only then is it moved into the verified store, where it is keyed by its digest.

The digest, not a per-image signature, carries the integrity chain. The controller signs the configuration ([Object signing](#object-signing)), the configuration carries the expected image digest, and EVE verifies the downloaded bytes against that digest. An attacker who can modify image bytes in the datastore or in transit therefore cannot get them accepted without also forging the controller's signature over the configuration.

EVE does not additionally verify a signature embedded in the image itself. Image provenance is therefore exactly as strong as the controller's object-signing key and the controller's own supply chain for the digests it publishes.

### What cannot be installed

EVE has no mechanism for adding software to the running system other than through the controller (the EVE API and, on EVE-k, also the Kubernetes API): base OS updates, application images and, on EVE-k with native Kubernetes orchestration enabled, Helm charts and Kubernetes manifests. The root filesystem is a read-only image replaced only as a whole partition; there is no package installation path, no shell available for installing binaries in a hardened configuration, and no way for an application to write into the EVE root filesystem.

The only code that runs outside the EVE base image is a workload the controller asked for, in its own isolation domain.

## Local access and platform dependencies

### The local console UI

EVE presents a text UI for a local operator on a physically attached monitor; neither the serial console nor an SSH session can reach it ([LOCAL-TUI](LOCAL-TUI.md)). It can set and revert the network configuration and, only before the device is onboarded, set the controller address. There is no authentication; physical presence is the control.

The controller address it can change is measured into PCR 14, so changing it causes attestation to fail and the vault to stay sealed at the next boot. The manual network configuration is not in `/config` and is not measured. Within the current boot, a redirected controller still cannot deliver usable configuration, because the object-signing roots in `/config` are not among the things the UI can change.

### What EVE relies on the hardware to provide

EVE's chain of trust begins after the platform has already executed several stages of code that EVE neither supplies nor measures, and EVE "relies on the fact that parts of the boot process that is out of the scope of EVE security, are not malicious and can't lie about the measurements" ([Hardware Security Recommendation](SECURITY-HARDWARE.md)). That document lists the properties EVE depends on but cannot enforce: a TPM 2.0 meeting the [platform assumption](#scope-and-platform-assumption), an honest initial measurement, protected SPI flash, authenticated firmware update with rollback protection, disabled or protected debug interfaces, and chassis intrusion detection. A deployment's actual security posture is the weaker of this document and the platform underneath it.

## Isolation between applications and EVE

### The compute boundary

The boundary between an edge application and EVE depends on the virtualization mode requested for that application in its configuration -- the `VmMode` field of the EVE API (see [vm.proto](https://github.com/lf-edge/eve-api/blob/main/proto/config/vm.proto)).

By default that boundary is a virtual machine, and this holds for edge applications delivered as OCI containers just as much as for those delivered as VM images. For a container, containerd prepares the container filesystem as a snapshot and the hypervisor-specific loader boots a VM from it, as described in [CONTAINERS.md](CONTAINERS.md) and [TASKS.md](TASKS.md). On EVE-k ([EVE-K.md](EVE-K.md)) the same container is launched as a shim VMI.

There are two deliberate exceptions, and in both the application runs as a native container on the host, with no VM around it.

The first is an application configured with `VmMode = NOHYPER` -- "Do not use a hypervisor":

* On the KVM configuration, such a task is handed to containerd rather than to the hypervisor, and runs as a container on the host.
* On EVE-k, it is created as a plain Kubernetes ReplicaSet rather than a KubeVirt `VirtualMachineInstanceReplicaSet`, so there is no launcher VM.

The second is a workload deployed through native Kubernetes orchestration on EVE-k ([EVE-K.md](EVE-K.md#modes)). Such workloads are deployed with Helm charts, manifests or other Kubernetes tooling rather than as EVE applications, and run as plain pods unless they request a KubeVirt VM.

For these workloads the boundary between application and EVE is industry-standard Linux and Kubernetes container isolation: namespaces, cgroups, and the container's capability set.

Two further properties follow from the absence of a VM:

* A `NOHYPER` application cannot be assigned a PCI device by passthrough, since there is no shim VM to assign it to. When a physical network adapter is direct-attached to such an application, EVE moves the interface into the container's network namespace and adds `CAP_NET_ADMIN` and `CAP_NET_RAW` to its capability set.
* The AppArmor profiles shipped with EVE confine EVE's own components -- `swtpm`, `vtpm`, `ptpm`, `tpm2`, `vector` and `guacd`. They are not applied to edge applications.

### The network boundary

Each application interface attaches to a network instance, and traffic on it is governed by an ordered access control list configured per interface ([NETWORK-ACLS](NETWORK-ACLS.md)). An implicit reject-all rule with ACE ID 0 terminates every list, so application traffic, apart from the implicit rules EVE adds for DNS, DHCP, IPv6 Neighbor Discovery and the local cloud-init service, is permitted only by explicit rule. With flow logging enabled, every flow is logged with the ID of the ACE that matched, including rejected flows; on a switch network instance rejected flows are not logged, because they are dropped before connection tracking records them. Air-gapped switch network instances give an application local connectivity with no path to any uplink.

## Logging and time

### What is recorded and where it lives

Device and application logs are collected under `/persist/newlog`. A collection file is closed and compressed when it reaches 550 KB or after 5 minutes, whichever comes first (10 seconds when fast upload is enabled), then queued for upload to the controller. Files that have been sent are retained on disk in a circular queue rather than deleted, so a device holds substantial log history locally.

All of this is outside `/persist/vault`, and therefore outside the encryption described in [Encrypted Application and User Storage](#encrypted-application-and-user-storage).

### Time

EVE runs an NTP client and keeps the system clock synchronized whenever connectivity allows; it also offers NTP service to applications, so guests can synchronize without their own uplink.

Certificate validity windows, EdgeView JWT expiry, and the ordering and timestamps of every log record uploaded to the controller all depend on time. EVE does not currently detect or report unauthorized alteration of its time source.

## Device lifecycle

### Onboarding

A factory-installed onboarding key (`/config/onboard.key.pem`) authenticates the device for one-time registration only ([REGISTRATION](REGISTRATION.md)). During registration the device presents its long-lived device certificate (`/config/device.cert.pem`, self-signed by the TPM-resident device key), and from that point the device key alone authenticates every subsequent connection. Any SSH access granted for pre-onboarding staging does not survive into operation: `/config/authorized_keys` is consulted only while the device has no controller-supplied global configuration. The file itself is left in place, so it remains visible to the PCR 14 measurement and to anyone who reads the drive.

A device that cannot reach a controller at first boot can instead be provisioned offline with a [bootstrap configuration](CONFIG.md#bootstrap-configuration), which is signed like any other configuration and subject to the same verification ([Object signing](#object-signing)).

There are several ways in which devices running EVE can be on-boarded to a controller. The details depend on the support available in the location, e.g., a factory, where the EVE software is installed on the device.

One approach is that EVE is booted and the TPM is used to generate the device certificate, and that device certificate is securely delivered from the factory to the intended end user of the device. That end user can then upload the device certificate to the controller to claim the device. (A controller would presumably check for attempts for more than one party claiming ownership of the same device hence so that a disclosed device certificate can be detected.)

Another approach is that an onboarding token (in the form of a certificate and private key) is added to the EVE image, but the factory does not need to boot EVE and upload information after installing the image. When the device boots EVE the first time at the installation site it will present the onboarding certificate and its hardware serial numbers using a register API call to the controller, and the user can scan and upload the serial number to the controller. This has weaker security especially if serial numbers can be guessed by an attacker having an account on the same controller, but different devices can be given different onboarding tokens to make such attacks more difficult.

The onboarding token lives in conf/onboard.*.pem in the repo, and this is used to build the config disk image which ends up in /config/ when EVE is booted. Thus the onboarding key UUID can be extracted using

```shell
openssl x509 -in conf/onboard.cert.pem -text | grep CN
```

The [generate-onboard.sh](../pkg/pillar/scripts/generate-onboard.sh) script can be used to generate such onboarding certificates.

A variant of that approach is to use a random soft serial number. When EVE is installed it generates a /config/soft_serial which is a random 128-bit UUID. If installed from a USB stick this serial number (together with the less random hardware serial number) are written to a directory on the USB installer stick. A device that boots a live image directly, without ever running the installer, generates the same random 128-bit UUID on its first boot instead, before it creates its device certificate, and reports it on the console. An image written to more than one device leaves /config/soft_serial empty for that reason, since a value carried in the image would make every device written from it present the same one.

When EVE is calling the register API it will present both the hardware serial and soft serial, hence if the controller has been told of the random soft serial for the device we avoid depending on guessable hardware serial numbers.

In both cases of calling the register API the factory can choose the granularity of the onboarding token. A single onboarding token can be used for a large production run of devices, or for fewer devices, or even be generated for each individual device. The choice depends on the capabilities of the factory installation site and the logistics of conveying the information (device certificate, onboarding tokens and/or serial numbers) from the factory to the end user.

### Decommissioning

Removing a device from the controller is sufficient as a decommissioning step. Like a stolen disk, a device removed from the controller might continue to run its applications, but it cannot be modified to get at the data: any change to its firmware, software or configuration moves a sealed PCR, and from then on only the controller can restore access to the vault by releasing the backup key.

In addition, a user can delete the application instances and their volumes from the controller before removing the device. That takes effect only if the device is powered on and can reach the controller.

A TPM clear from the BIOS makes the encrypted vault completely unreadable ([Destroying the vault without reading it](#destroying-the-vault-without-reading-it)).

### What the device reports about itself

EVE reports its hardware inventory, its running software version and its update state to the controller. This is the data an operator uses to answer "which of my devices are running something with a known vulnerability".

The software bill of materials for an EVE image is produced as part of the image build and is retrievable from the image itself; it is not currently delivered to the controller as part of device reporting.

## Behavior when the controller is unreachable

[DISCONNECTED-OPERATION](DISCONNECTED-OPERATION.md) describes this in detail. In security terms, an unreachable controller fails safe: the vault key stays sealed to the previous PCR values and cannot be resealed until the controller accepts the new measurements.

Operation continues indefinitely. Nothing about the outage stops application instances, and nothing expires the configuration they run under. The device keeps a checkpoint of the last configuration it received and replays it when it boots, with no age limit on that checkpoint; EVE prefers the backup checkpoint when the previous boot ended in a panic or watchdog reset, so a bad configuration cannot drive a reboot loop. A power failure therefore returns the device to service unattended: the vault key unseals from the TPM without a controller round trip, provided nothing PCR-visible changed in the meantime, such as a BIOS update. The device certificate is valid for twenty years, so nothing in the identity chain ages out during any realistic outage.

Three limits bound that indefinite operation:

* The device reboots after a configured period without controller connectivity (`timer.reboot.no.network`, seven days by default). This is recovery machinery, not a policy limit on disconnected operation: a hung network interface, driver or firmware is not otherwise detectable from userspace. Deployments that would rather keep applications running across a long outage raise the value.
* Log history is capped, at 2 GB or 10% of `/persist`, whichever is smaller (`newlog.gzipfiles.ondisk.maxmegabytes`). Over the cap, the oldest files go first, and the queues are consumed in order: already-uploaded, upload-failed, application, device.
* Time has to be right before remote fetches work. A device whose real-time clock drifted needs NTP to resynchronize, which a controller outage does not affect. TLS tolerates a fair amount of clock error; the datastores EVE downloads images from are markedly less forgiving, so image downloads are the first thing to fail after a period without a clock and the last to recover.

Two optional local paths survive the outage, and they differ in what they are trusted to do. A Local Operator Console substitutes for the controller and serves the whole device configuration, but that configuration is signed by the controller, so a LOC distributes controller-authored configuration rather than authoring its own. A Local Profile Server ([LPS](LPS.md)) carries only local operations -- profile selection, application restart, radio silence, graceful shutdown -- authenticated by a token the controller provisioned beforehand and not signed.

What stops is the controller relationship itself: no configuration change reaches the device, and no state, metrics or logs reach the operator until the connection returns. The security posture does not weaken while disconnected, because the vault stays sealed to the state it was sealed in and no new configuration, application or base image can be introduced by anyone.

## Summary

| Property | Mechanism |
|----------|-----------|
| Controller authenticity | Root CA pinned in the read-only CONFIG partition; controller address changeable only at the local console, before onboarding; both measured into PCR 14, so a change is detected |
| Device authenticity | TPM-resident device key; device cert exchanged at onboarding |
| Config integrity | Object signing (ECDSA) over TLS; prevents proxy modification |
| Config confidentiality | Object encryption (ECDH/AES-256) per device, when the controller encrypts the field; secrets never leave the responsible microservice |
| No inbound attack surface | Outbound-only polling model; no listening application ports on management interfaces; on EVE-k, cluster ports on the cluster interface |
| Remote access auditability | EdgeView: WSS relay, JWT expiry, command signing, per-command log |
| Remote access control | SSH keys managed by the controller after onboarding (`debug.enable.ssh`); EdgeView requires a live controller JWT |
| Disk theft protection | Vault key PCR-sealed to the TPM; vault content useless without the exact device and software stack; logs, `/persist/status` and CONFIG are outside the vault |
| Upgrade continuity | Two-party NBDE-style backup key requiring both the device TPM and the controller's acceptance of the attested PCRs |
| Post-upgrade re-validation | Re-attestation on every boot; integrity-token invalidated if PCRs change |
| Hardware root of trust | TPM 2.0 (SHA-256 bank); optional Intel Boot Guard in Measured Boot mode |

### What a stolen or copied disk reveals

No application data or volumes. The vault is encrypted, and its key is sealed to TPM PCRs and never written to the disk. Without the exact device's TPM, in exactly the attested firmware and software state, the vault content is inaccessible. The controller's copy of the backup key is TPM-encrypted and equally inaccessible without that device's TPM, so the disk together with the controller database still yields nothing from the vault.

Everything outside the vault is readable: the device's log history under `/persist/newlog`, the state EVE's services publish to `/persist/status`, and the CONFIG partition. Secrets the controller sends with object-level encryption stay encrypted in the stored configuration, and reading them also needs the device's ECDH private key, which is in the TPM.

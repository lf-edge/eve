# OBJECT LEVEL ENCRYPTION

## Motivation

Independent of the use of TLS in the [API](https://github.com/lf-edge/eve-api/tree/main/APIv2.md) and [object signing](https://github.com/lf-edge/eve-api/tree/main/OBJECT-SIGNING.md) there are some secrets in the device configuration API (such as datastore credentials, WiFi credentials, and cloud-init user data) which should have minimal exposure by

1. keeping them in some vault inside a controller implementation
2. not exposing them to any microservices in a controller except for the party which decrypts from the vault and re-encrypts for a particular device
3. not exposing them to all microservices on the device and accidentally storing them in files or putting them in logs (note that EVE checkpoints the last received config protobuf message in /persist/checkpoint)
4. potentially restricting it by policy on the device so that in a defense-in-depth implementation only the downloader can access datastore credentials, only nim can access WiFi credentials (basically least privilege approach)
5. MiTM proxies and server-side load balancers which terminate TLS should not be able to see this information

## Overview

The approach is to encrypt such credential and other private information using a per-device key, and doing this encryption before assigning it to the fields which get protobuf encoded. Thus other microservices in a controller and the device will pass them along as any protobuf to golang data structure, but the content will be encrypted.

This means that the protobuf API will have new fields which are the encrypted fields (with the old username/password fields etc still in place as we transition away from only protecting this using TLS).

And it requires that the controller and the device can create an encryption key, and a mechanism to re-key from either end. The shared encryption key is created using the standard ECDH based on a ECC key pair on the controller and an ECC  key pair on the device for this purpose, where each end shares their certificate containing the ECC public key.

## ECDH key agreement

[Elliptic Curve Diffie Hellman(ECDH)](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) Key Exchange is used for establishing a shared secret key based on the ECC certificates. ECDH does itself not provide authentication of the two endpoints, but the fact that the certificates are exchanged between the device and the controller using TLS plus object signing provide for that authentication.

The shared secret is fed through SHA-256 as a key derivation function per [NIST SP 800-56A Rev. 3](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final) and [FIPS PUB 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final).

The derived key is used an [AES 256 CTS key](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) with an initialization vector passed from the controller as part of the device configuration message. This key and IV are then used for encrypting the sensitive information between the controller and the device.

The ECC certificates used in the exchange are:

1. A certificate that the device creates during first install, specifically for ECDH operations. This is different than the device certificate because the TPM key used for device cert is a Signing key, it does not support Decryption. For ECDH to work, TPM expects a key with Decryption set and Signing unset.

1. A certificate that the controller deploys for this purpose. This needs to be signed by the root CA that the devices trust (stored in /config/root-certificate.pem) via zero or more intermediaries. The controller can generate new certificates at any time which provides forward secrecy.

The controller publishes its certificate using [ZControllerCert](https://github.com/lf-edge/eve-api/tree/main/APIv2.md#controller-certificates) and the device publishes its certificate using [ZEveCert](https://github.com/lf-edge/eve-api/tree/main/APIv2.md#attestation), as described in the [API](https://github.com/lf-edge/eve-api/tree/main/APIv2.md#messages) specification.

## Sender authentication

ECDH does not provide sender authentication. But the certificates used for ECDH are sent over the secure channel between the peers (which consists of transport security between the TLS endpoints and the object signing providing integrity and sender authentication between the microservice endpoints). That the sender authentication and integrity means that an attacker can not replace the certificates used for ECDH.

(Perfect) Forward Secrecy is provided by having the controller periodically generate a new ECC certificate.

## API components

In addition to the above mechanisms for the controller and device to send their ECC certificates, there are several specific pieces in the EVE API to carry the state needed for encryption and re-keying.

### Cipher Contexts

The [Cipher Context](https://github.com/lf-edge/eve-api/tree/main/proto/config/acipherinfo.proto#L26) is a construct used for defining hash algorithms, key exchange schemes like ECDH, etc., encryption schemes like AES256, etc., and certificate hashes used for the encryption by the controller.

### Cipher Block

The [Cipher block](https://github.com/lf-edge/eve-api/tree/main/proto/config/acipherinfo.proto#L47) is a construct which has a cipher context id, [IV](https://en.wikipedia.org/wiki/Initialization_vector), encrypted data and hash of clear text (used for verification after decryption). Cipher block is a part of the object configuration which has encrypted data.

### Encryption Block

The [Encryption block](https://github.com/lf-edge/eve-api/tree/main/proto/config/acipherinfo.proto#L66) is a construct used for encryption by the controller. The controller fills the encryption block with sensitive information and then encrypts it and provides encrypted data in the cipher block.

## EVE packages

### Cipher Package

The [cipher](../pkg/pillar/cipher/handlecipher.go) package is called by the agents which want to decrypt the sensitive information. Caller provides cipher block and subscription contexts of controller certificates and cipher contexts.

The cipher packet takes the cipher context id from the cipher block and then subscribes for that cipher context to the zedagent. Cipher context has the hashes of all the certificates which are required for the decryption.

It implements the crypto operations required to retrieve the shared key from the controller, and also interacts with TPM (if present) for ECDH operations and returns an encryption block to the caller after decryption.

## EVE agents

Following are the key agents in EVE, which are involved in implementing this solution:

### TPM Manager

TPM Manager creates ECDH certificates using the TPM, and also implements the glue layer to talk to [go-tpm](https://github.com/google/go-tpm) for ECDH APIs.

For devices without a the ECDH key-pair is created in software, and the ECDH exchange will invoke software crypto packages instead of interacting with TPM.

TPM Manager publishes the device's ECDH certificate using [types.AttestCert](../pkg/pillar/types/attesttypes.go#L68) to zedagent, for sending to the controller.

### Zedagent

1. Zedagent [fetches](../pkg/pillar/cmd/zedagent/handlecertconfig.go#L22) the ECDH controller certificate, along with other certificates during boot-up and publishes them to the different agents using [types.ControllerCert](../pkg/pillar/types/certinfotypes.go)
2. Zedagent receives the device configuration from the controller and parses cipher contexts and publishes them to the different agents using [types.CipherContext](../pkg/pillar/types/cipherinfotypes.go)
3. Zedagent publishes the ECDH certificate received from TPM manager to the controller.

### Downloader

For downloading images from private data stores, downloader need to decrypt the data store credentials.

Downloader passes the cipher context and controller certificate subscription contexts and cipher block from the datastore config to the cipher package for the decryption.

The datastore credentials are only kept in memory in the downloader.

### Network Interface Manager

Nim needs to decrypt the WiFi credentials available in device port configuration for setting up the wlan connectivity. Nim calls the [device network](../pkg/pillar/devicenetwork) package for parsing the device port configuration.

Nim passes device port configuration and subscription contexts of controller certificates and cipher contexts to the device network package. And, device network package passes received subscription contexts and cipher block from the WiFi configuration to the cipher package for the decryption.

Decryption of WiFi credentials is very important if the device has only wlan connectivity, and depends on the key information being published persistently so that the ECDH calculation and decryption can be performed on reboot before the device can communication with the controller.

The WiFi credentials are only kept in memory in nim, however in order to hand them to the wpa_supplicant process they are stored in /run which is a filesystem backed by memory.

### Domain Manager

Domain manager needs to decrypt the sensitive user data from the app instance configuration used for cloud-init and for container environment settings. Depending on the application instance such information can include local and remove keys and credentials.

Domain manager passes the cipher block from the app configuration and subscription contexts of controller certificates and cipher context to the cipher package for the decryption.

The user data are only kept in memory in the domainmgr, but for cloud-init it is used to create a CDROM image which is passed to the application. This CDROM image lives in `/run/domainmgr/cloudinit` which is a filesystem backed by memory.

## Refreshing of the controller certificates in EVE

Zedagent fetches the controller certificates at boot using the `ControllerCerts` API. But we also need a mechanism of refreshing the controller certificates in EVE if the controller certificates get updated when the device is already running. This is TBD.

There are two ways to get updated certificates:

1. We can include hashes of the certificates on the top level of the device configuration itself. With the help of it, we can parse the certificates from the device configuration in zedagent and will fetch the certificates if changed.
2. If we don’t want to add the hashes of certificates in the device configuration then we can add a decryption retry mechanism in the cipher package. So if decryption fails because of a certificate not found error, we will identify that the certificate required for the decryption is not available in the device and will fetch the controller certificates and trigger the decryption retry mechanism.

Second approach is more complex because the decryption is done in different EVE microservices.

# API Object Signing

In the V2 API, in addition to using TLS for server/proxy authentication and encryption, the API uses object signing using the [auth.AuthContainer](./proto/auth/auth.proto) to provide end-to-end integrity of the message payloads.

## Motivation

The motivation for this is two-fold:

- TLS Man-in-the-Middle proxy products and server-side load balancing and DDoS protection services do not work well with TLS client certificates and the restricted single server root CA certificate used in the V1 API.
- The requirement to be able to carry signed edge-node configuration through some non-TLS channel such as a USB memory stick, e.g., for initial device networking configuration.

## Authentication and Protection

In the TLS MiTM proxy case, the device will trust the proxy at the TLS level either because it is trusted by being in the standard Linux root certificate list, or because it was specified in the `proxyCertPEM` field in the device configuration API. Thus server TLS still provides authentication and privacy plus integrity of the server communication.

But since there is no TLS client authentication the `AuthContainer` message wrapper is used to sign the payloads from the device to the controller. And since we want to prevent a MiTM proxy or load balancer from accidentally or intentionally modifying message payloads the 'AuthContainer' wrapper is used from origin server to EVE as well.

In the non-network delivery case, e.g. USB, there is no _server_ TLS to provide authentication of the message. But a message signed by the controller using the `AuthContainer` message wrapper containing the EdgeDevConfig message can be trusted subject to timestamp checks to avoid using old configuration.

In combination, message payloads from device to controller, or controller to device, in addition to any server TLS, is encrypted and signed in the body, allowing full functioning when:

- TLS client certificates can not be used due to MiTM proxies or server-side load balancers
- MiTM proxies are trusted to inspect the payloads but should be prevented from modifying the payloads
- message delivery is not on a network channel

Note that the endpoints and trust/certificate authorities are different for TLS and object signing. TLS is terminated at a MiTM proxy (if present) and at certain server-side load balancers. Object signing is between some specific microservcie in EVE and a specific microservice in a controller.
And the TLS trust using the standard set of root certificate authorities are subject to many of the [concerns for the web PKI](https://www.schneier.com/academic/paperfiles/paper-pki.pdf). The object security in the V2 API is trusting a single root CA for the controller and that CA is selected when the device is initially installed.

## Signing and verification

The sender of a message has a its own certificate and associated private key plus a protobuf encoded payload.

The `AuthContainer` wrapper is constructed by:

1. Put the above payload in the `protectedPayload` field
1. Compute Sha256 over the above payload
1. Compute the ECDSA signature of that sha, and place it in the `signatureHash` field
1. To identify the sender, place a truncated sha of the sender's certificate in `senderCertHash`
1. Place the algorithm used for the truncated sha in the `algo` field. Currently it's either a SHA256-32bytes or SHA256-16bytes. Note that `senderCertHash` is just for a lookup at the receiver, hence it can be truncated to be a lot shorter without any security implications.
1. For the case when the receiver might not be able to identify the sender using just the hash, place the full sender's certificate in the `senderCert` field. This is the base64 standard encoding of the PEM format of the certificate. (This is used for the `register` API during onboarding.)

The steps to verify a `AuthContainer` message wrapper are:

1. Verify that the `algo` is a supported algorithm.
1. If the `senderCert` field is set, use that base64 encoded PEM format certificate to determine who the sender is, and whether it is authorized to access the particular API endpoint
1. Else, use the `senderCertHash` to look up the sender. The result of the lookup will be the sender's certificate, and information about what is it authorized to access.
1. Compute Sha256 over the `protectedPayload` bytes
1. Using the public key from the sender's certificate, verify the ECDSA signature in the `signatureHash`
1. If all successful, pass the identity of the sender to subsequent senders so they can make authorization checks (For instance, in a controller a device can only access API endpoints for its own UUID and the UUID is associated with the device certificate.)

## Certificate management

The above assumes that the receiver knows the certificate of the sender.
On the controller this is straight forward since the device certificate is known to the controller once the device has been onboarded/registered, and the EVE specification requires that a device's certificate to be immutable, such that changing the certificate effectively means it is a brand-new device. Thus there is no need for an API for a device to update its device certificate.

However, on the device the certificate handling is different since the controller can and will roll its signing certificate periodically.
The device uses the `ControllerCerts` API to fetch the signing certificates and any intermediate certificates. The received certificate chain is then verified using up to the trusted root CA configured at birth of the device.

The fetch using `ControllerCerts` is required at install time and when the `senderCertHash` does not match a certificate already known to the device. Thus the controller can roll certificates as long as it makes them available using the `ControllerCerts` API and puts the hash of the signer's certificate in the `senderCertHash` field; that will make the device re-issue a GET of `ControllerCerts`.

During the initial device onboarding the `register` API might be used. Since the controller might not know all of the onboarding certificates a-priori the device MUST include the full `senderCert` in the `AuthContainer`.

## Implementation of signining and verification

The signing uses standard ECDSA signing operations implemented in ecdsa golang package alternatively the Sign function from github.com/google/go-tpm/tpm2 when the device private key is in a TPM.

The verification uses standard ECDSA verification function from the ecdsa golang package.

The certificate chain received from the controller is verified using the standard go X.509's package VerifyChain up to the trusted root CA configured at birth of the device (In EVE this is kept in /config/root-certificate.pem and is orthogonal to the set of trusted root CAs used for TLS).

The EVE code implementing the above is in [pkg/pillar/zedcloud/authen.go](../pkg/pillar/zedcloud/authen.go)

## Onboarding sequence

The controller has TLS and signing certs, and the device has its device cert plus an onboarding certificate (the device certificate is generated earlier during the first boot of the device using a TPM if available).

When using the `register` message to onboard the sequence is:

- device boots up
- device checks for presence of initial network configuration in this order of preference:
  1. bootstrap.pbuf in config partition
       - if present, device first checks config signature against root_certificate using signing and intermediate certificates attached in bootstrap.pbuf
       - if signature verification succeeded, (network) configuration is applied, which should open connectivity with the controller
  2. legacy override.json (config partition) or usb.json (USB stick)
       - if present, the (network) config is loaded and applied (no signature to verify), which should open connectivity with the controller
  3. if no initial configuration is present, device will by default configure all ethernet ports for management and will try DHCP to get IP/DNS settings
- device sends a GET for `ControllerCerts` retrieving the payload signing and intermediate certificates used by the controller
  (this is done regardless if there is bootstrap config with embedded signing/intermediate certs)
- device verifies the signing certs up to the root CA certificate the device trusts since birth
- device sends the `register` POST call to upload it's device.cert and serial number to controller. This is signed using the onboarding certificate's priavate key and wraooed in the `AuthContainer` message
- the controller inspects the onboarding certificate and compars serial number to determine whether this is a legitimate new device, and verifies that the `protectedPayload` is signed by using the onboarding public key.

The device then proceeds with the POST of `ConfigRequest` as below.

## Booting sequence

The controller has TLS and signing certs, and the device has its device certificate.

The sequence during boot is:

- device boots up
- device uses persisted network configuration to (re-)open connectivity with the controller
- if device does not have the controller certificates, it sends a GET for `ControllerCerts` (it might also do this on every boot)
- if the device retrieved the controller certs, then it verifies the signing certs up to the root CA certificate the device trusts since birth
- device invokes the `ConfigRequest` API call get its EdgeDevConfig. This is signed using the device certificate and the `AuthContainer` message per above
- the controller looks up the device certificate based on the `senderCertHash` and if found verifies that the `protectedPayload` is signed by using the device public key.

Subsequence info and metrics messages from the device use the same approach.

# Registration

This document describes how an EVE device registers with a Controller on first boot. It complies with the official "Device API" available [here](../api/APIv2.md).

1. Device reads its configuration from its `/config/` partition, which contains the following files:
    * `server` - contents are the FQDN to the Controller for this Device
    * `onboard.cert.pem` and `onboard.key.pem` - the onboarding public certificate and private key, respectively
    * `root-certificate.pem` - the certificate of the CA that signed the Controller's certificate
    * `v2tlsbaseroot-certificates.pem` - the list of trusted TLS root certificates to be used in conjunction with the [object signing](../api/OBJECT-SIGNING.md) to get end-to-end protection through content-inspecting TLS proxies.
1. Device constructs all requests to `https://<contents_of_server_file>/<endpoint>`, for example, if contents of `server` are `api.zededa.com:885`, then the `ping` endpoint is at `https://api.zededa.com:885/api/v2/edgedevice/ping`
1. Device generates a unique device certificate (using a TPM if available) if it not exists and saves it in the `/config/` partition as `device.cert.pem`. If there is no TPM it also saves a `device.key.pem` in that partition. In addition, if the device has a TPM the certificate is saved in NVRAM in the TPM (so the device identity is not lost if the disk needs to be replaced.)
1. Device sends a `POST` request to the `register` endpoint, using the onboarding certificate for sender authentication, per the API, with body contents of a `ZRegisterMsg`, including the hardware serial, soft serial, and device certificate in the message

If registration fails, the device continues to retry to register. Since the controller might not yet have pre-registered the device's onboarding certificate or serial, retries provide it with the ability to eventually succeed.

To handle the case when the device certificate is registered with the controller out of band, during above process the device also tries to retrieve its UUID by calling the /api/v2/edgeDevice/uuid API endpoint. If this succeeds it means the device is already registered with the controller.
To handle the case when the registration in the controller has been manually deleted and it needs to register again, `register` called on every reboot of device in case of available onboarding certificates.
`register` and `uuid` requests are interleaved, so it covers both cases.

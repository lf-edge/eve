# Registration

This document describes how an EVE device registers with a Controller on first boot. It complies with the official "Device API" available [here](../api/APIv2.md).

An EVE device, on boot, first determines if it already is registered, then, if it is not, runs the registration process.

## Determine If Registration Is Necessary

On boot, the device looks in `/config/` partition to determine if it has registered:

* If no `device.cert.pem` file exists, then device has not registered, begin registration process in the next section.
* If the `device.cert.pem` file exists and file `self-register-pending` exists, registration has potentially stalled mid-stream, thus continue registration process in the next section.
* If no file `self-register-pending` exists, and the `device.cert.perm` file exists, device has registered, exit registration process.

## Register If Necessary

1. Device reads its configuration from its `/config/` partition, which contains the following files:
    * `server` - contents are the FQDN to the Controller for this Device
    * `onboard.cert.pem` and `onboard.key.pem` - the onboarding public certificate and private key, respectively
    * `root-certificate.pem` - the certificate of the CA that signed the Controller's certificate
    * `v2tlsbaseroot-certificates.pem` - the list of trusted TLS root certificates to be used in conjunction with the [object signing](../api/OBJECT-SIGNING.md) to get end-to-end protection through content-inspecting TLS proxies.
1. Device constructs all requests to `https://<contents_of_server_file>/<endpoint>`, for example, if contents of `server` are `api.zededa.com:885`, then the `ping` endpoint is at `https://api.zededa.com:885/api/v1/edgedevice/ping`
1. Device creates a file in `/config/` partition named `self-register-pending`, with no contents, as a transaction lock file that registration is in process
1. Device generate a unique device certificate (using a TPM if available) and saves it in the `/config/` partition as `device.cert.pem`. If there is no TPM it also saves a `device.key.pem` in that partition. In addition, if the device has a TPM the certificate is saved in NVRAM in the TPM (so the device identity is not lost of the disk needs to be replaced.)
1. Device sends a `POST` request to the `register` endpoint, using the onboarding certificate for sender authentication, per the API, with body contents of a `ZRegistrerMsg`, including the hardware serial, soft serial, and device certificate in the message
1. Once the registration is accepted, the device removes the `self-register-pending` file from the `/config/` partition.

If registration fails, the device continues to retry to register. Since the controller might not yet have pre-registered the device's onboarding certificate or serial, retries provide it with the ability to eventually succeed.

To handle the case when the device certificate is registered with the controller out of band, during above process the device also tries to retrieve its UUID by calling the /api/v2/edgeDevice/uuid API endpoint. If this succeeds it means the device is already registered with the controller.

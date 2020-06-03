# Registration

This document describes how an EVE device registers with a Controller on first boot. It complies with the official "Device API" available [here](../api/APIv2.md).

An EVE device, on boot, first determines if it already is registered, then, if it is not, runs the registration process.

## Determine If Registration Is Necessary

On boot, the device looks in `/config/` partition to determine if it has registered:

* If no files `device.cert.pem` and `device.key.pem` exist, device has not registered, begin registration process in the next section.
* If files `device.cert.pem` and `device.key.pem` exist and file `self-register-pending` exists, registration has potentially stalled mid-stream, continue registration process in the next section.
* If no file `self-register-pending` exists, and files `device.cert.perm` and `device.key.pem` exist, device has registered, exit registration process.

## Register If Necessary

1. Device reads its configuration from `/config/` partition, which contain the following files:
    * `server` - contents are the FQDN to the Controller for this Device
    * `onboard.cert.pem` and `onboard.key.pem` - the onboarding public certificate and private key, respectively
    * `root-certificate.pem` - the certificate of the CA that signed the Controller's certificate
1. Device constructs all requests to `https://<contents_of_server_file>/<endpoint>`, for example, if contents of `server` are `api.zededa.com:885`, then the `ping` endpoint is at `https://api.zededa.com:885/api/v1/edgedevice/ping`
1. Device creates a file in `/config/` partition named `self-register-pending`, with no contents, as a transaction lock file that registration is in process
1. Device generate a unique device key and certificate and saves them to persistent location. As of this writing, it is in the `/config/` partition as `device.cert.pem` and `device.key.pem`. In the future, it may be in a tpm or other hardware key/certificate generation and storage mechanism.
1. Device sends a `POST` request to the `register` endpoint, using the onboarding certificate for mTLS authentication, per the API, with body contents of a `ZRegistrerMsg`, including the device serial and device certificate in the message
1. Once registration is accepted, Device removes from `/config/` partition file `self-register-pending`

If registration fails, the device continues to retry to register. Since the controller might not yet have pre-registered the device's onboarding certificate or serial, retries provide it with the ability to eventually succeed.

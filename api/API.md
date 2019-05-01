# API

This document defines the API for Device to Controller communications.

## Definitions

1. `Device`: an independent 

* zmet: device -> controller
* zconfig: controller -> device

## API endpoints

* `POST /api/v1/edgedevice/register` for device onboarding. Returns one of the following:
    * `201` - successful registration. 
    * 
* `GET /api/v1/edgedevice/ping` for connectivity test; return `200`, empty message, ignores payload
* `GET /api/v1/edgedevice/config` complete device + instance config
* `POST /api/v1/edgedevice/info` for triggered device/instance status
* `POST /api/v1/edgedevice/metrics` for periodic device/instance metrics
* `POST /api/v1/edgedevice/logs` for logs from microservices on device

All except `POST register` use device cert for mTLS.

Every device has UUID by the CloudController and sent in the config (should be part of the API), sent in response to `GET config`, and used in all other requests by device. Message `message EdgeDevConfig` is the root of response to `/config`, UUID is in there.

`GET /config` does not pass anything to controller, headers or trees or hashes or anything, right now, so every time we get the whole thing.

### info posting

Event triggered updates to state from device to controller, for different objects. Includes the following:

* Updated version of baseos image
* Partition switch
* Application instance - application has Linux bridge - following lifecycle of application instance. 

Look at messages in `zmet/*.proto`, specifically anything `ZInfo`.

How often and what triggers is an implementation question; the definition of _what_ is reported is an API question.

`Info` messages are intended to be reliable, and should not be lost. This is distinct from metrics.


### metrics

Metrics are numeric data points. Associated with apps, network instances or devices (similar to Info). One message sent periodically that carries all the metrics. It is sent once per frequency (implementation independent), root message is `message ZMetricMsg` is the root.

Frequency is configured along with all other config variables/config items. The API is agnostic to them, just passes them along. The current list is [here](https://github.com/zededa/eve/blob/master/pkg/pillar/docs/global-config-variables.md).

QUESTION: should these be part of the API? Or some?

The message passes them along at `message ConfigItem`, which is a dumb key-value pair.

### logs

Logs are passed in groups of `message LogBundle`, which contain multiple `message LogEntry`. Combined for maximum size (any POST up to 64kB), plus timer, "do not wait longer than x seconds to send."

Should be guaranteed delivery.

Q: what if it runs out of memory or storage? Our log manager stores to loca disk, but this is a policy question.
### registration

Possible responses:

```
enum ZRegisterResult {
        ZRegNone         = 0;
        ZRegSuccess      = 1;
        ZRegNotActive    = 2;
        ZRegAlreadyDone  = 3;
        ZRegDeviceNA     = 4;
        ZRegFailed       = 5;
}
```

Onboard message:

```
message ZRegisterMsg {
       string onBoardKey = 1; // deprecated

       bytes pemCert = 2;
       string serial = 3;
}
```

Flow is expected as follows:


(this part should be kept private)

1. New device manufactured, contains EVE image; OR existing device is flashed with EVE
2. Manufacturer extracts unique cryptographic information from device, e.g. public key from tpm, or generate new public/private keypair and stores private on device
3. Ship with those public keys on a separate medium - QR on box, label on box, USB key, email, printed paper - and send to end-user
4. When device comes up, it registers with cloud controller. As we see it arrive on cloud controller, it shows up with public key information. Users can then choose which to accept.

(end private)

This leads to device registration:

1. Device boots
(assuming not yet registered)
2. Device read config from `config` partition, which contains a `server` file, whose contents are an FQDN
3. It finds a device certificate in `config` partition `device.cert` and `device.key` file, which contain the key/cert (code on way to use tpm)
4. It finds an onboarding certificate in `config` partition `onboard.cert` and `onboard.key`, which contain the onboarding key/cert
5. Connects via SSL to `https://<contents_of_server_file>/<endpoint listed above>`. In `config` partition, we have root CA cert we trust. Can use whatever they want.
6. It does `POST device register` end point. Register endpoint uses onboarding cert for mTLS. 
    * Can register any number of onboarding certs for my account (zedcloud capability) - unknown onboarding cert is rejected as `401` (`403`?)
    * Once authenticated with mTLS, submits `ZRegisterMsg` message with unique device cert and serial number
    * Can have any of the following:
        * accepts: new device with serial number that has not been used before
        * reject: serial number unknown (serial number has to be pre-registered in our implementation, but this is implementation-specific)
        * reject: serial number already registered with different device
    * How is the onboarding cert restricted to my account in the cloud controller? It is not now.
    * When connected and auth-ed via mTLS, it then takes the serial+onboarding cert, uses them to find the customer, and now ties device to customer, unless serial already registered
    * Map potential responses to http codes
7. Once registration is accepted, record that it has been registered in `config` through files:
    * Save the device certificate
    * In process, create a file called `self-register-failed`, which exists until registration has succeeded. It is a transaction lock file.
    * Create `failed` file, create device cert/key file, register, remove `-failed` file.
    * Once successful, it is done


#### Serial conflict resolution

In theory serials can conflict between manufacturers, e.g. SuperMicro + RaspberryPi. We resolve it by having different onboarding certs per manufacturer, possibly manufacturer+customer (e.g. general SuperMicro, GE+SuperMicro, etc.)


## Pillar local

Is there a way to run pillar locally, not on a device?


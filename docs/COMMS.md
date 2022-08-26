# Communications

This document describes the components in EVE that are responsible for
communications between an EVE instance and a Controller. Read about the API for Device to Controller Communications [here](https://github.com/lf-edge/eve/blob/master/api/APIv2.md)

All of these are components of [pkg/pillar](../pkg/pillar/), which is the set
of process, commands and services responsible for managing an EVE device.

## Overview

An EVE instance is controlled via a Controller. EVE is responsible for:

* Opening a communications channel with its Controller
* Requesting its configuration on a regular basis
* Updating any of its components that require updating based on the updated configuration
* Communicating any events, such as logs or metrics, that need to be sent to the Controller

## Architecture

Within `pillar`, each process, command or service that needs to communicate
with the Controller does so directly; there is no local proxy or buffering
engine process that stands between these processes and the Controller.

However, common logic for communications is extracted out to the package
[pkg/pillar/zedcloud](../pkg/pillar/zedcloud/). Each service that needs to
communicate with the Controller imports the `zedcloud` package and uses its
functions to communicate with the Controller.

The overall architecture is as follows.

    +--------------------------+
    |        Controller        |
    ++---+---+---+---------+---+
     ^   ^   ^   ^         ^
     |   |   |   |         |
     |   |   |   |         |
     |   |   |   |         |
     v   v   v   v         v
    +++ +++ +++ +++      +-+--+
    |z| |z| |z| |z|      | zc |  *zc = zedcloud package
    |c| |c| |c| |c|      |    |
    | | | | | | | |      |    |
    | | | | | | | |      |    |
    | | | | | | | |      |    |
    |l| |n| |d| |c|      | z  |
    |o| |i| |i| |l|      | e  |
    |g| |m| |a| |i|      | d  |
    |m| | | |g| |e|      | a  |
    |a| | | | | |n|      | g  |
    |n| | | | | |t|      | e  |
    |a| | | | | | |      | n  |
    |g| | | | | | |      | t  |
    |e| | | | | | |      |    |
    |r| | | | | | |      |    |
    +++ +++ +++ +++      +--+-+
     ^   ^   ^   ^          |
     |   |   |   |          v
     +---+---+---+----------+
     |        pubsub        |
     +----------------------+

### zedcloud - communications

In EVE, the shared functionality for communications with the Controller is
encapsulated in the [zedcloud](../pkg/pillar/zedcloud) package. All services
communicate with the Controller using functions provided via the `zedcloud`
package.

`zedcloud` is responsible for:

* Creating SSL channels
* mutual TLS (mTLS) and client authentication
* Handling http logic, including status codes
* Retries in case of loss of communication
* Using multiple management ports to communicate with the controller

`zedcloud` does _not_ currently handle protobuf analysis. It is blissfully
unaware of the contents of most messages in both directions. It simply makes
the request on behalf of, and passes the response back to, the requesting
functions.

The logic in the services themselves do the following:

* Package up any messages to be sent in protobuf
* Pass the message to functions in `zedcloud`
* Receive the response from `zedcloud`
* Unpack the received protobufs

### services

The following are a few of the key services that communicate with the
Controller via the functions provided in the `zedcloud` package.

#### zedagent

[zedconfig](../pkg/pillar/cmd/zedagent) is the service responsible for retrieving
configuration from the Controller and updating locally running services on EVE.
Like all other services communicating with the Controller, it does so through
functions provided by the `zedcloud` package.

`zedagent` is responsible for the following:

* Maintaining a regular cycle for retrieving configuration or updates from Controller.
* Requesting the configuration from the Controller via functions in `zedcloud`.
* Receiving the latest correct configuration in response to its request.
* Saving the latest correct configuration locally.
* Loading the initial (aka bootstrap) device configuration if present (see [CONFIG.md](./CONFIG.md))
* Informing any services of changes to their relevant configurations via [pubsub](../pkg/pillar/pubsub), which allows those services to restart or make changes in response to the updated configuration.

#### loguploader

[Loguploader](../pkg/pillar/cmd/loguploader) is the service responsible for
uploading device and application gzip logs to controller. It does
so through the functions provided by the `zedcloud` package.

#### client

[client](../pkg/pillar/cmd/client) is the service responsible for registering
the EVE device with the Controller, as well as retrieving the initial
configuration, as part of onboarding a new device to the Controller.

#### nim

[Network interface manager](../pkg/pillar/cmd/nim) is responsible for managing
local network interfaces on the device, as well as checking connectivity to the
Controller and retrieving the config for testing communications purposes. All
communications with the Controller are performed via the functions provided by
the `zedcloud` package.

#### diag

[Diagnostics](../pkg/pillar/cmd/diag) is responsible for managing diagnostic
services on the device, and reporting to console for debugging if there are
issues. It does not send information to the Controller. However, among its
diagnostic tests, it does test the ability to reach both the ping and config endpoints
of the Controller. To connect and test these endpoints, it uses the functions
provided by the `zedcloud` package.

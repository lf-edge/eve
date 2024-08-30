# VComLink: Asynchronous Communication Channel for Host-VM Interaction

## Overview

VComLink is a communication agent that facilitates asynchronous communication between a host and virtual machines (VMs) through the use of the vsock protocol. The primary goal of VComLink is to provide a simple and efficient mechanism for sending and receiving requests between the host and VMs. For simplicity, VComLink processes one request per read/write operation.

## VSOCK Communication

VComLink utilizes vsock, a communication protocol designed specifically for VM-host interactions. The vsock communication channel operates on a unique port `2000`. This port enables the guest VM to establish a connection with the host.

## Channel and Request Identifiers

VComLink uses two primary identifiers to manage communication:

- `ChannelID`: Uniquely identifies a communication channel between the host and a VM.
- `RequestID`: Uniquely identifies a specific request within a communication channel.

These identifiers are defined as types in `pkg/pillar/vcom`.

### Channels

- `ErrorChannel`: Channel dedicated to handling error responses (ID 1).
- `ChannelTpm`: Channel dedicated to handling TPM (Trusted Platform Module) related requests (ID 2).

### Request Identifiers

The following request identifiers are associated with specific channels:

- `RequestTpmGetEk`: Request to retrieve the TPM Endorsement Key (ID 1).

## Data Structures

VComLink utilizes the following JSON-formatted data structures to handle communication between the host and VMs. All packets in VComLink are derived from the Base struct. It includes the channel ID to ensure that packets are routed correctly.

### Error message

The Error struct is used to send error messages from the host or VM.

```json
{
  "channel": 1,
  "error": "Error message"
}
```

- `channel`: An integer representing the channel ID, in this case 1 for error.
- `error`: A string containing the error message.

### TPM Request Packet

The TpmRequest struct is used for sending TPM-related requests.

```json
{
  "channel": 2,
  "request": <num>
}
```

- `channel`: An integer representing the channel ID, in this case 2 for TPM related requests.
- `request`: An unsigned integer representing the specific TPM request ID.

### TPM Response Packet

The TpmResponseEk struct is used to send the response for a TPM Endorsement Key request.

```json
{
  "channel": 2,
  "ek": "Endorsement Key"
}
```

- `channel`: An integer representing the channel ID, in this case 2 for TPM related requests.
- `ek`: A string containing the TPM Endorsement Key.

## Example Workflow

1. Establishing a Connection: The guest VM connects to the host using the predefined vsock port (2000).

2. Sending a Request: The guest sends a TpmRequest packet via the ChannelTpm channel, with RequestTpmGetEk as the request identifier.

3. Receiving a Response: The host processes the request and sends back a TpmResponseEk packet containing the TPM Endorsement Key.

4. Handling Errors: If any error occurs during the request, the host returns an Error packet on the Error channel.

```bash
$ # send a request to get the ek
$ echo -n '{"channel":2,"request":1}' | socat - VSOCK-CONNECT:2:2000
{"channel":2,"ek":"AAEACwADALIAIINxl2..."}
$ # send an invalid request
$ echo '{"channel":-1,"request":-1}' | socat - VSOCK-CONNECT:2:2000
{"channel":1,"error":"received malformed packet"}
```

## Extensibility

VComLink is designed to be extensible. New channels and requests can be added by defining additional ChannelID and RequestID constants, as well as creating corresponding request/response structs in JSON format.

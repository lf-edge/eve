# Radio Silence Implementation

Radio silence is the act of disabling all radio transmission for safety or security reasons.
To learn more about this feature in terms of use-cases, design decisions, terminology and APIs,
please refer to the user-facing EVE documentation, section [WIRELESS](../../../docs/WIRELESS.md#Radio-silence).

Radio silence implementation is split between 3 EVE microservices:

* `zedagent`: If Local profile server is deployed and running, the microservice [makes a POST
  request to the Radio endpoint every 5 seconds](../cmd/zedagent/radiosilence.go).
  In the request body, it publishes the current state of all used wireless devices, which it obtains
  from the `DeviceNetworkStatus` (`DNS` for short; the message is received from NIM). Radio silence
  status in encapsulated by `RadioSilence` structure, embedded into `DNS`. It contains a `ChangeInProgress`
  boolean, which NIM uses to inform that an operation of switching radio silence ON/OFF is still in progress
  and that zedagent should therefore pause Radio endpoint POST requests until it finalizes.

  Whenever the Local profile server responds with a radio silence configuration that differs from
  the current state, zedagent will record the new intended radio state into `RadioSilence` structure
  embedded into `ZedAgentStatus`. zedagent will also record the time of the request in `RadioSilence.ChangeRequestedAt`.
  NIM should then copy this timestamp to `DeviceNetworkStatus.RadioSilence` to match the request with the
  corresponding state update (see below).

  When zedagent sees `DeviceNetworkStatus` with `RadioSilence` where `ChangeRequestedAt` equals
  the last configuration request time and `ChangeInProgress` has changed to false, it knows
  that the operation has finalized and it can publish the status up to the Local profile server.

* `NIM`: Receives `ZedAgentStatus` with the intended radio silence state.
  With each new publication of `ZedAgentStatus`, it first checks if `RadioSilence.ChangeRequestedAt`
  is greater than the timestamp of the last seen radio configuration change. If it is the case, it copies
  `ChangeRequestedAt` from `ZedAgentStatus.RadioSilence` to `DeviceNetworkStatus.RadioSilence`,
  sets `ChangeInProgress` to `true` and starts switching radios of wireless devices ON/OFF.
  For WiFi adapters, this is done by directly [calling the rfkill command](../devicenetwork/wlan.go).
  For cellular modems, NIM updates the configuration file `/run/wwan/config.json`, which is picked up
  by the `wwan` microservice, and waits for the status update published in `/run/wwan/status.json` (see below).
  Once NIM is done with all radio devices, it updates `RadioSilence` of `DeviceNetworkStatus` and sets
  `ChangeInProgress` to false and `Imposed` (boolean) to reflect the actual radio silence state
  (could be different from the intended state if operation failed). If the operation fails, it also shares
  all error messages with zedagent, to be published up to the Local profile server.

* `wwan`: Microservice implemented as a [shell script](../../wwan/usr/bin/wwan-init.sh), which manages
  cellular modems, including the state of radio transmission. It receives the intended configuration
  from NIM through the file `/run/wwan/config.json`. A boolean field `radio-silence` is used to order
  the microservice to either enable or disable radio transmission on all cellular modems visible to the host.
  For QMI-controlled modems, it calls `uqmi -d <device>  --set-device-operating-mode <persistent_low_power|online>`.
  For MBIM-controlled modems, it  calls `mbimcli -d <device> --set-radio-state <on|off>`.
  State updates (including the actual state of radio transmission) is published as `/run/wwan/status.json`.
  It includes a SHA256 hash of the last applied configuration. It is used by NIM to wait for a config
  update to be fully applied, without any operations still ongoing, and to process and publish status update
  which corresponds to the new config.

To summarize, the indented radio configuration flow is:

```text
Local profile server --POST-response--> zedagent --ZedAgentStatus--> NIM --/run/wwan/config.json--> wwan
                                                                         --> rfkill ((un)block wlan)
```

And the status update flow is:

```text
wwan --/run/wwan/status.json--> NIM --DeviceNetworkStatus--> zedagent --POST-request--> Local profile server
         rfkill exit status -->
```

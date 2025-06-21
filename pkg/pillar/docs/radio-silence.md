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
  boolean, which NIM (specifically DPCManager component) uses to inform that an operation of switching
  radio silence ON/OFF is still in progress and that zedagent should therefore pause Radio endpoint
  POST requests until it finalizes.

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
  For WiFi adapters, this is done by directly [calling the rfkill command](../dpcreconciler/linuxitems/wlan.go).
  For cellular modems, NIM updates and publishes new `WwanConfig` via pubsub, which is received
  by `mmagent` of the `wwan` microservice. NIM then waits for the status update from `wwan`
  published through pubsub topic `WwanStatus`. To avoid NIM processing obsolete `WwanStatus`,
  corresponding to an older `WwanConfig` and thus not reflecting the latest radio config,
  `ChangeRequestedAt` from the radio config is appended to `WwanConfig` by NIM (as well as DPC
  key + timestamp), which is copied to `WwanStatus` by `mmagent` only once this config has been
  fully applied. Using this mechanism, NIM is able to ignore obsolete wwan status updates.

  Once NIM is done with all radio devices, it updates `RadioSilence` of `DeviceNetworkStatus` and sets
  `ChangeInProgress` to false and `Imposed` (boolean) to reflect the actual radio silence state
  (could be different from the intended state if operation failed for any of the wireless devices).
  If the operation fails, it also shares all error messages with zedagent, to be published up
  to the Local profile server.

* `wwan`: Microservice running [ModemManager](https://modemmanager.org/), controlling WWAN (2G/3G/4G/5G)
  devices and connections, and [mmagent](../../wwan/mmagent), a Go program build on top of the pillar
  infrastructure (pubsub, agentbase, logging, etc.), acting as a translation layer between declarative
  EVE cellular API and imperative ModemManager API. More information about this microservice
  can be found in [WIRELESS.md](../../../docs/WIRELESS.md). What is important here, is that the input
  (i.e. wwan config) is received by mmagent from NIM via pubsub as `WwanConfig`. A boolean field
  `RadioSilence` is used to order the microservice to either enable or disable radio transmission
  on all cellular modems visible to the host. mmagent uses [SetPowerState][set-power-state] method
  of the [DBus][dbus]-based [ModemManager API][mm-api]. It sets `MM_MODEM_POWER_STATE_LOW` for
  a given modem if radio silence is enabled or if the modem is not managed, i.e. it is not configured
  by the controller. Otherwise, `MM_MODEM_POWER_STATE_ON` is set to enable radio transmission functions.
  State updates (including the actual state of radio transmission) are published as `WwanStatus`.
  Included is identification of the last applied configuration. This consists of several fields that
  NIM appends to `WwanConfig`, referencing the sources of the configuration (DPC key+timestamp,
  RadioSilence timestamp), which are then simply copied to `WwanStatus` by `wwan` microservice
  when the config is fully applied. This allows NIM to wait for a config update to be fully processed,
  without any operations still ongoing, and to prepare and publish DeviceNetworkStatus that correctly
  reflects the new config. Having sources of `WwanConfig` identified also helps with debugging.
  For a given `WwanConfig`, it is possible to go backwards in logs and trace the origins of the
  corresponding DPC and RadioSilence config that `WwanConfig` was generated from.

To summarize, the indented radio configuration flow is:

```text
Local profile server --POST-response--> zedagent --ZedAgentStatus--> NIM --WwanConfig--> wwan (mmagent --SetPowerState--> ModemManager)
                                                                         --> rfkill ((un)block wlan)
```

And the status update flow is:

```text
wwan (ModemManager --(Get)PowerState--> mmagent) --WwanStatus--> NIM --DeviceNetworkStatus--> zedagent --POST-request--> Local profile server
                                          rfkill exit status -->
```

[dbus]: https://www.freedesktop.org/wiki/Software/dbus/
[set-power-state]: https://www.freedesktop.org/software/ModemManager/api/latest/gdbus-org.freedesktop.ModemManager1.Modem.html#gdbus-method-org-freedesktop-ModemManager1-Modem.SetPowerState
[mm-api]: https://www.freedesktop.org/software/ModemManager/api/latest/ref-dbus.html

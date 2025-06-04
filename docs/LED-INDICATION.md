# LED Indication

As EVE-OS boots and progresses through various intermediate states, the LED (by default the disk LED) blinking
pattern changes to indicate state transitions.
To indicate a given state, LED blinks one or more times quickly in a row, then pauses for 1200ms and repeats continuously.
By counting the number of successive blinks one may determine the current state of the edge device.

The following table summarizes all states that LED is able to indicate. Please note that blink counts of less than 10
are used for initial device states from booting up to the onboarding. Everything above is used for run-time errors
that deserve user attention.

| Blink count | State Description |
| --- | --- |
| 0   | State is unknown. Device is most likely still in early booting stages. |
| 1   | Device is waiting for DHCP IP address(es) on management interface(s). |
| 2   | Device is attempting to connect to the Controller. |
| 3   | Device has connected to the Controller but it is not yet onboarded. |
| 4   | Device is connected to the Controller and onboarded.  |
| 5   | Radio silence is imposed (wireless transmission is disabled). |
| 6-9 | *unused* |
| 10  | Device onboarding is failing (generic). |
| 11  | *unused* |
| 12  | Controller replied without TLS connection state. |
| 13  | Controller replied without OCSP response. |
| 14  | Failed to fetch or verify Controller certificate. |
| 15  | Received message from the controller with invalid or missing signature. |
| 16  | Bootstrap configuration (see [CONFIG.md](./CONFIG.md)) is not valid. |
| 17  | Device onboarding is failing due to conflict with another device. |
| 18  | Device onboarding is failing due to not being found in the controller. |

Application status is also displayed using LEDs on device model SIEMENS AG.SIMATIC IPC127E
Uses LED3 (the one labeled as L3 MAINT) for application state.

1. If no application has even started booting then LED3 will be off.
2. If one or more applications is in error state, then the LED3 will be solid red.
3. If there is no error
    - If EVE has moved all of the applications to the booted or running state, then solid green
    - If some applications are in the halting state, then blinking orange.
    - If some applications are in the init state, then blinking green.

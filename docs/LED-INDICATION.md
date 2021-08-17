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
| 5-9 | *unused* |
| 10  | Device onboarding is failing. |
| 11  | *unused* |
| 12  | Controller replied without TLS connection state. |
| 13  | Controller replied without OCSP response. |
| 14  | Failed to fetch or verify Controller certificate. |

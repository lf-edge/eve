# Fault injection in EVE

EVE is detecting and recovering from a multitude of faults such as

- failure to boot (using hardware watchdog)
- hangs post boot (using hardware watchdog)
- device driver issues which result in loss of communication with the controller (using the timer.reboot.no.network timer to reboot)
- processes crashing (using the Linux watchdog daemon and pid files)
- key goroutines in the pillar services getting stuck (using the Linux watchdog daemon and touch files)
- the above failures during an update of the EVE image (when the resulting reboot results in a fallback to the previous image)
- failure to reach the controller after a change to the systemAdapterList [config API](https://github.com/lf-edge/eve-api/tree/main/proto/config/devconfig.proto) which results in a fallback to the old systemAdapterList

For some of the above we can explicitly inject faults.
For instance, one can unplug the network cable to cause network failures or run an iptables setup which drops all communication to the controller.

There is also an application called /opt/zededa/bin/faultinjection which can cause various failures in the zedbox process and verify that the Linux watchdog daemon detects it and also reports it to the controller.

The options for faultinjection are:

- F: cause a log.Fatal which will make zedbox exit after logging the error
- P: cause a golang runtime panic which will make zedbox exit (the watchdog-report.sh script tries to extract the panic info and save it)
- H: cause the faultinjection service, after registering its touch file with the Linux watchdog daemon, to never touch that file. This will result in the Linux watchdog daemon rebooting the system after recording the stack traces in /persist/agentdebug/.
- W: cause the faultinjection service to check and kill the software watchdog with the intent that the hardware watchdog will fire.

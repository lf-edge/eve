# EVE microservices for device and app instance management

For information about EVE see https://www.lfedge.org/projects/eve/

This is included in zenbuild (https://github.com/zededa/zenbuild) to produce the EVE images.

The onboarding of devices is done by scripts/device-steps.sh, and after onboarding that script proceeds to start the agents implementing the various microservices. That script runs on each boot. Once the agents are running they are operated from the controller using the API specified in https://github.com/zededa/api

The agents are:
 - ledmanager - make LEDs light/blink for feedback to the person installing the hardware
 - nim - network interface manager (ensures that there is connectivity to the controller)
 - waitforaddr - merely waiting for a few minutes max for IP address(es) for a more orderly boot in the normal case.
 - zedagent - communicate using the device API to the controller to retrieve configuration and send status and metrics
 - logmanager - send logs to the controller for debugging of these agents
 - baseosmgr - handle updates of the base OS (hypervisors plus all of the services which make up EVE) using dual partitions for fallback
 - downloader - download objects like images and certificates
 - verifier - verify cryptographic checksums and signatures on downloaded objects
 - zedmanager - drive the application instance lifecycle
 - zedrouter - drive the lifecycle for the connectivity for the instances. Includes services like DHCP, DNS, and Access Control Lists. Provides different connectivity like local, switch, cloud, and mesh networks.
 - domainmgr - interface with the hypervisor to start and stop application images. Includes performing device assignment.
 - identitymgr - used when mesh networks desire locally created key pairs for the cryptographic application instance identities

In addition there are debugging tools like
 - diag - prints the state of the connectivity on the console each time there is
   a change.
 - ipcmonitor - subscribes to the agents/collections passed between the different microservices


 

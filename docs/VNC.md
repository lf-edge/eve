# VNC

There is an option to connect to every ECOs UI via VNC.
To enable it, the flag [EnableVnc](https://github.com/lf-edge/eve-api/blob/a2b011fedf87918e924bf11b5be3216b3d5d13a8/go/config/vm.pb.go#L121) needs to be set in the respective EdgeAppConfig.

The VNC support is built into the KVM/QEMU hypervisor and is available for all types of ECOs.
However there is a special case for the container applications: the flag `EnableVnc` let's the user connect to the container's UI via VNC, however if the user wants to be able to connect to the shim VM as well, the flag [EnableVncShimVm](https://github.com/lf-edge/eve-api/blob/a2b011fedf87918e924bf11b5be3216b3d5d13a8/go/config/vm.pb.go#L141) needs to be set additionally.
Please note that `EnableVncShimVm` can only be activated if `EnableVnc` is set to true.
If both flags (`EnableVnc` and `EnableVncShimVm`) are enabled the user will be able to switch between the container and the shim VM session by pressing a key combination.

The other option to enable VNC to the shim VM is to set the `debug.enable.vnc.shim.vm` to true, which acts as a global flag for the whole node, unlike the `EnableVncShimVm`, which is a per-application flag.

## Guacamole

EVE has a [guacamole](https://guacamole.apache.org/) server running as a service, which allows the user to connect to the ECOs via a web browser.
Alternatively to connecting over guacamole, the user can configure the forwarding of the VNC port to the host machine and connect to the ECOs via a VNC client.
To enable direct access to EVE's ports 5900 - 5999 from external IPs, the global configuration option `app.allow.vnc` needs to be set to `true`.
It's default value is `false`, meaning that only local access to the VNC ports is allowed.
For such cases the VNC ports can be forwarded e.g. via SSH tunneling.

## Switching between the container and the shim VM session

When connecting to the QEMU instance via VNC the user will first be presented with a view of the currently running process (container's entry point).
To switch to the shell of the shim VM the user will have to press 'Ctrl+Alt+2' and then 'Enter' to get the login prompt.
Due to inability of some VNC clients to change the resolution of the display, the client might crash.
However upon the client restart the new virtual console will appear as expected.
The user can then switch back to the previous virtual console by pressing 'Ctrl+Alt+1'.

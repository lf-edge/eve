For some of the wifi adapters we have to work around a pretty nasty issue
of when firmware load gets triggered. Most of the time it gets triggered
during either explicit modprobe or initial boot (bus scan) loading of the
corresponding device driver. In a few cases (most notably with Panda Wireless
Ralink rt2800usb) it actually gets triggered during the first use of the
interface. This, in turn, leads to a situation where if something like
   ip link set wlan0 up
gets executed from within a container (or even from within chroot) the
kernel tries to locate firmware files in a filesystem rooted in a container/chroot
as opposed to the top level root. 

Picking between the two evils we've decided to simply make /lib/firmware
available inside wlan container. However, this may prove hard to track
if the "use" events start coming from different containers. At which point
the following workaround may be useful at the rootfs.yml level:
   - name: fw_force_load
     image: linuxkit/modprobe:v0.5
     command: ["/bin/sh", "-c", "for i in `ls -d /sys/class/ieee80211/*/device/net/* 2>/dev/null | sed -e 's#^.*/##'`; do ip link set $i up ; ip link set $i down ; done"]
     binds:
       - /lib/firmware:/lib/firmware
       - /lib/modules:/lib/modules
       - /sys:/sys
     capabilities:
       - all

Finally, there's also upstream linuxkit discussion around this going on here:
  https://github.com/linuxkit/linuxkit/pull/3217 

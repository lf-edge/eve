// Package uevent implements a Linux kernel uevent reader and decoder.
// The reader uses a Netlink (AF_NETLINK) socket to listen to kernel udev events (see netlink(7)).
// The decoder takes an arbitrary io.Reader and decodes Uevent objects.
package uevent

# Test Description

This test creates and assigns a network to 2 applications, which communicate.
One has nginx, the other uses curl.
Creates 2 networks, checks internal IPs and does intercommunication

[E-script test for networks](testdata/test_networking.txt).

## Test structure

eden.network.tests.txt - escript scenario file

* /image - a folder with docker image
* Dockerfile with nginx, dhcpcd and curl based on Debian
* dhcpcd.conf - setup for dhcpcd
* entrypoint.sh - entrypoint for Docker which runs required workload
(curl, nginx, ip, dhcpcd)
* nw\_test.go - source of networks detector
* supervisord.conf - processing params and run strings for workloads
* /testdata - a folder with custom escripts for a workload
* test\_networking.txt - main test file

## Network state detector

The syntax for calling this detector is:

```console
eden.network.test [options] state nw_name...
```

Where "status" is the standard state of the network (for example, ACTIVATED)
or "-" to detect deletion of network.

Test specific "options":

* -timewait -- Timewait for waiting (1 min by default).

[E-script test for network](testdata/network_test.txt).

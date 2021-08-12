# Test Description

Tests described here uses docker image (Dockerfile is available [here](image/Dockerfile)) called eclient, which one
provides SSH access on port 22 for user root with certificate available [here](image/cert/id_rsa). Container includes
additional bash scripts for testing purposes and implementation of
[local profile server](https://github.com/lf-edge/eve/blob/master/api/PROFILE.md).

## Test structure

* eden.eclient.tests.txt - escript scenario file
* /image - a folder with eclient docker image
* /testdata - a folder with custom escripts for a workload
* eden+ports.sh, eden-ports.sh - modifies port forwarding configuration (`eden+ports.sh 2223:2223` - adds 2223/TCP->2223/TCP forwarding)
* qemu+usb.sh, qemu+2usb.sh, qemu+audio.sh - add devices to qemu

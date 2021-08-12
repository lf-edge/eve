# Test Description

This test runs a [FLEDGE](https://www.lfedge.org/projects/fledge/) project workload.
This workload deploys a FLEDGE demo docker image, connects to
Flir Thermal Imaging Device(AX8 and other A Series cameras), and getting data.

## Requrements

Set up the `CAMERA_IP` and `CAMERA_PORT` variables for running test.

## Test structure

eden.flir.tests.txt - escript scenario file

* /image - a folder with fledge docker image
* /testdata - a folder with custom escripts for a workload
* test_flir.txt - main test file

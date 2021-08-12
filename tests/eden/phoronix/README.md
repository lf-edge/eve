# Test Description

This test creates and runs an application with phoronix test suite inside.

[E-script test with phoronix](testdata/test_phoronix.txt).

## Test structure

* eden.phoronix.tests.txt - escript scenario file
* phoronix/test_phoronix.txt - escript test, which deploys an app and waits for result served with http
* /image - a folder with docker image
* Dockerfile with phoronix-test-suite based on Ubuntu
* entrypoint.sh - entrypoint for Docker which runs required test of testsuite and serve results via http

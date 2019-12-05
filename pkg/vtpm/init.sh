#!/bin/sh

#Launch the VTPM server
mkdir jail; cd jail
/usr/bin/vtpm_server > vtpm_server.log 2>&1

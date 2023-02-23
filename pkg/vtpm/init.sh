#!/bin/sh

cd jail || exit;
#Too much stdout noise from tpm2_tools and vtpm_server,
#so redirecting stdout to /dev/null. But stderr will be
#picked up by logging infra as usual
/usr/bin/vtpm_server > /dev/null

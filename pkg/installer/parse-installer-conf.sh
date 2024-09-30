#!/bin/bash
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

CMDLINE=$(cat /proc/cmdline)
INSTALLER_CONF="/installer.json"

# Parse the installer JSON using jq and create an associative array
declare -A assoc_array
while IFS="=" read -r key value; do
    if [ "$value" == "" ];
    then
        continue
    fi
    key=$(echo "$key" | tr '[:upper:]' '[:lower:]')
    assoc_array["$key"]="$value"
done < <(jq -r "to_entries|map(\"\(.key)=\(.value|tostring)\")|.[]" $INSTALLER_CONF)

# edit the cmdline and add the configuration inserted by installer.json
for key in "${!assoc_array[@]}"; do
    key=$(echo "$key" | tr '[:upper:]' '[:lower:]')
    echo "Key: $key, Value: ${assoc_array[$key]}"
    PROC_VALUE=$(<"/proc/cmdline" tr ' ' '\012' | grep "${key}")
    value="${key}=${assoc_array[$key]}"

    if [ "$PROC_VALUE" != "" ];
    then
        CMDLINE="${CMDLINE/$PROC_VALUE/$value/}"
    else
        CMDLINE="${CMDLINE} ${value}"
    fi
done
echo "$CMDLINE" > /tmp/newcmdline
cat /tmp/newcmdline

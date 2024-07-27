#!/bin/sh
#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#

# Background monitoring non-ssh related tasks
monitor_file_and_execute_tasks() {
    # edgeview request to generate collect-info and remove tar.gz file
    # the protocol is for edgeview to create a file
    # /run/edgeview/edgeview-request-collect-info, and debug container
    # run 'collect-info.sh' to generate the tar.gz file, when the job is
    # done, remove the file /run/edgeview/edgeview-request-collect-info.
    # edgeview can also request to remove the tar.gz file by creating
    # /run/edgeview/edgeview-request-remove-tar.gz file, and debug container
    # will get the file name and remove the generated tar.gz file.
    #
    last_check_time=$(date +%s)
    while true; do
        if [ -f "/run/edgeview/edgeview-request-collect-info" ]; then
            echo "edgeview request to run collect-info..."
            # the newlog part of the collection, only collect last 10 days,
            # and add 'edgeview' to tarball name
            /usr/bin/collect-info.sh -t 10 -e
            # remove the request file
            echo "edgeview request collect-info done"
            rm /run/edgeview/edgeview-request-collect-info
        fi
        # edgeview request to remove tar.gz file by sending the suffix string of the
        # file name to remove, the file to remove is eve-info-edgeview-$suffix
        if [ -f "/run/edgeview/edgeview-request-remove-tar-gz" ]; then
            fileSuffixToRemove=$(cat /run/edgeview/edgeview-request-remove-tar-gz)
            fileToRemove="/persist/eve-info/eve-info-edgeview-$fileSuffixToRemove"
            echo "edgeview request to remove $fileToRemove file"
            if [ -f "$fileToRemove" ]; then
                rm "$fileToRemove"
            fi
            # remove the request file
            rm /run/edgeview/edgeview-request-remove-tar-gz
        fi

        current_time=$(date +%s)
        diff=$((current_time - last_check_time))
        if [ $diff -ge 86400 ]; then # check every 24 hours
            last_check_time=$current_time

            if find "/persist/eve-info" -type f -name "eve-info-edgeview-v*.tar.gz" | grep -q .; then
                # Find and delete files matching the pattern and older than 10 days
                find "/persist/eve-info" -type f -name "eve-info-edgeview-v*.tar.gz" -mtime +1 -print0 | xargs -0 rm -f

                echo "Deleted files older edgeview generated eve-info-edgeivew-v*.tar.gz"
            fi
        fi

        sleep 10
    done
}

# Start the monitoring and execute tasks
monitor_file_and_execute_tasks
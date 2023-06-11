#!/bin/sh
#
# profiles are located in /etc/apparmor.d, loop over and load them.
for profile in /etc/apparmor.d/*; do
    if [ -f "$profile" ]; then
        /usr/bin/apparmor_parser -Kr "$profile";
    fi
done

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:24.04

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        avahi-daemon curl iproute2 iputils-ping openssh-server python3 && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir /run/sshd /srv/www

RUN echo 'root:testpassword' | chpasswd
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Advertise "evetest-local-ds.local" over mDNS (no D-Bus in the container),
# including the "workstation" service that EVE's local datastore lookup
# queries first.
COPY avahi-daemon.conf /etc/avahi/avahi-daemon.conf

EXPOSE 22 80

COPY init.sh /
CMD ["/bin/bash", "/init.sh"]

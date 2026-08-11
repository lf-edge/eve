# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# pkg/witness ships the same kube-init binary as pkg/kube, told by the
# role file below which of the two it is. Lifting it from that image
# rather than rebuilding keeps the two roles on identical code: they
# share a k3s version, a config vocabulary and a set of pubsub types,
# and a skew between them would surface as a cluster that half agrees
# with itself.
#
# The tag below must be bumped whenever pkg/kube changes. It is the git
# tree hash of pkg/kube, printed by `make kube-show-tag`;
# check-docker-hashes-consistency is what catches a stale one.
FROM lfedge/eve-kube:6486beadf1ca5ead71352423400bee74b609c436 AS kube

FROM lfedge/eve-alpine:5f1c625e658308db22e936e3e5498167ed7b9081 AS build
ARG TARGETARCH
# iproute2 is not used by the witness itself; it is there because this
# container has a network namespace of its own, and diagnosing what NIM
# put in it from anywhere else is guesswork.
ENV PKGS="alpine-baselayout musl-utils iproute2"
RUN eve-alpine-deploy.sh

# etcdctl drives the membership calls the witness makes: confirming it
# has become a voting member, and removing itself when it stops being
# wanted. Keep in step with pkg/kube's copy, which talks to the same
# etcd.
ENV ETCDCTL_VERSION=v3.5.5
ADD https://github.com/etcd-io/etcd/releases/download/${ETCDCTL_VERSION}/etcd-${ETCDCTL_VERSION}-linux-${TARGETARCH}.tar.gz /tmp/etcd.tar.gz
RUN mkdir -p /out/usr/bin /tmp/etcdtmp && \
    tar -xzf /tmp/etcd.tar.gz -C /tmp/etcdtmp && \
    cp "/tmp/etcdtmp/etcd-${ETCDCTL_VERSION}-linux-${TARGETARCH}/etcdctl" /out/usr/bin/etcdctl && \
    chmod +x /out/usr/bin/etcdctl && \
    rm -rf /tmp/etcd.tar.gz /tmp/etcdtmp

# Register etcdctl in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n etcdctl -v "${ETCDCTL_VERSION}" -l Apache-2.0 -u https://github.com/etcd-io/etcd

# Selects the role, for the daemon and for every tool beside it. The
# only mechanism, in the shape of /etc/eve-hv-type, so there is nothing
# for it to disagree with. It has to reach the tools too: /run is
# shared, so both supervisor sockets are reachable from in here, and a
# k3s-sctl that guessed kube would answer for the node's daemon rather
# than fail.
RUN echo witness > /out/etc/kube-init-role

FROM scratch
COPY --from=build /out/ /
COPY --from=kube /usr/bin/kube-init /usr/bin/kube-init
COPY --from=kube /usr/bin/k3s-sctl /usr/bin/k3s-sctl

# No k3s binary and no config.yaml, unlike pkg/kube. The witness reuses
# the k3s that pkg/kube publishes to the vault, so the rootfs does not
# carry a second copy, and it renders every drop-in it needs from Go.
ENTRYPOINT []
CMD ["/usr/bin/kube-init"]

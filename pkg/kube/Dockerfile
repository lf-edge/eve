# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# The only declaration of the KubeVirt release. Declared above the first
# FROM so every stage can pick it up with a bare `ARG KUBEVIRT_VERSION`.
ARG KUBEVIRT_VERSION=v1.7.3

# sriov-cni upstream image is used only as a source of the prebuilt sriov
# binary; we copy it into our final image at build time so we don't need a
# DaemonSet at runtime just to stage the binary on each node.  Pinned by
# digest for reproducibility.  v2.7.0 ships amd64 only, matching the
# previous DaemonSet's nodeSelector.
#
# Declare this stage BEFORE `build` so all the build-stage RUN/COPY commands
# below (eve-alpine-deploy, etcdctl, eve-bridge, etc.) execute inside `build`
# and not inside this passthrough stage — otherwise the COPY --from=sriov-cni-bin
# below ends up referencing the stage it's running in (circular dependency).
#
# hadolint DL3029 forbids literal --platform on FROM; we silence it here because
# upstream sriov-cni ships an amd64-only image and we need the amd64 binary
# regardless of the build host's architecture (e.g. arm64 host cross-building
# the kube image).  BUILDPLATFORM/TARGETPLATFORM wouldn't pin the source image
# to amd64, which is what we actually need.
# hadolint ignore=DL3029
FROM --platform=linux/amd64 ghcr.io/k8snetworkplumbingwg/sriov-cni@sha256:fce504e683275ab59215065ddf6433ca80d1b4b53f0d4b0cdf037da6701c7cb4 AS sriov-cni-bin

FROM lfedge/eve-alpine:5f1c625e658308db22e936e3e5498167ed7b9081 AS build

ARG TARGETARCH
ENV PKGS="alpine-baselayout musl-utils iproute2 iptables curl openrc \
         open-iscsi libvirt libvirt-client util-linux grep findutils jq \
         cni-plugins nfs-utils inotify-tools sqlite"
RUN eve-alpine-deploy.sh

ENV ETCDCTL_VERSION=v3.5.5
ADD https://github.com/etcd-io/etcd/releases/download/${ETCDCTL_VERSION}/etcd-${ETCDCTL_VERSION}-linux-${TARGETARCH}.tar.gz /tmp/etcd.tar.gz
RUN mkdir -p /out/usr/bin /tmp/etcdtmp && \
    tar -xzf /tmp/etcd.tar.gz -C /tmp/etcdtmp && \
    cp "/tmp/etcdtmp/etcd-${ETCDCTL_VERSION}-linux-${TARGETARCH}/etcdctl" /out/usr/bin/etcdctl && \
    chmod +x /out/usr/bin/etcdctl && \
    rm -rf /tmp/etcd.tar.gz /tmp/etcdtmp
COPY --from=sriov-cni-bin /usr/bin/sriov /out/usr/bin/sriov

# Register etcdctl in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n etcdctl -v "${ETCDCTL_VERSION}" -l Apache-2.0 -u https://github.com/etcd-io/etcd

# pillar's RolloutDiskToPVC reads only virtctl image-upload's stderr: it
# relies on the progress bar and status lines going to stdout, and on the
# returned error ("already successfully imported" included) going to stderr.
# Re-verify that split when bumping this version.
ARG KUBEVIRT_VERSION
ADD https://github.com/kubevirt/kubevirt/releases/download/${KUBEVIRT_VERSION}/virtctl-${KUBEVIRT_VERSION}-linux-${TARGETARCH} /tmp/virtctl
RUN install /tmp/virtctl /out/usr/bin/virtctl && rm -f /tmp/virtctl
# Register virtctl in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n virtctl -v "${KUBEVIRT_VERSION}" -l Apache-2.0 -u https://github.com/kubevirt/kubevirt

COPY eve-bridge /plugins/eve-bridge
WORKDIR /plugins/eve-bridge
RUN GO111MODULE=on CGO_ENABLED=0 go build -v -ldflags "-s -w" -mod=vendor -o /out/usr/bin/eve-bridge .

COPY cert-gen /plugins/cert-gen
WORKDIR /plugins/cert-gen
RUN GO111MODULE=on CGO_ENABLED=0 go build -v -ldflags "-s -w" -o /out/usr/bin/cert-gen .

COPY update-component /plugins/update-component
WORKDIR /plugins/update-component
RUN GO111MODULE=on go build -v -ldflags "-s -w" -mod=vendor -o /out/usr/bin/update-component .

COPY stale-mount-cleanup /plugins/stale-mount-cleanup
WORKDIR /plugins/stale-mount-cleanup
RUN GO111MODULE=on CGO_ENABLED=0 go build -v -ldflags "-s -w" -mod=vendor -o /out/usr/bin/stale-mount-cleanup .

# kube-init is the Go daemon that replaces cluster-init.sh. The
# binary built here is the container's entrypoint; k3s-sctl is the
# operator-facing CLI client that talks to its control socket.
COPY kube-init /plugins/kube-init
WORKDIR /plugins/kube-init
RUN GO111MODULE=on CGO_ENABLED=0 go build -v -ldflags "-s -w -X github.com/lf-edge/eve/pkg/kube/kube-init/versions.KubeVirt=${KUBEVIRT_VERSION}" -mod=vendor -o /out/usr/bin/kube-init . && \
    GO111MODULE=on CGO_ENABLED=0 go build -v -ldflags "-s -w" -mod=vendor -o /out/usr/bin/k3s-sctl ./cmd/k3s-sctl

FROM scratch
ARG KUBEVIRT_VERSION
COPY --from=build /out/ /
RUN mkdir -p /usr/bin/kube/

# Kube general path for all manifests before applying to each cluster mode
RUN mkdir -p /etc/kube/
RUN mkdir -p /etc/k3s-manifests
COPY manifests/* /etc/k3s-manifests/

# upgrades
COPY update-component/expected_versions.yaml /etc/
RUN printf 'kubevirt: "%s"\n' "${KUBEVIRT_VERSION}" >> /etc/expected_versions.yaml
COPY update-component/settings_longhorn.yaml /etc/

# k3s
RUN mkdir -p /etc/rancher/k3s
COPY config.yaml /etc/rancher/k3s
COPY debuguser-role-binding.yaml /etc/
COPY k3s-pod-logs.sh /usr/bin/
COPY all-kube-events.sh /usr/bin/
COPY cfg-manifests/04-multinode-watch-cache.yaml /etc/kube/

# Manifests the daemon applies at first boot. Stays under /etc; the
# Go components/ package reads them by path.
COPY multus-daemonset.yaml /etc
ADD https://github.com/kubevirt/kubevirt/releases/download/${KUBEVIRT_VERSION}/kubevirt-operator.yaml /etc
RUN sed -i -e '1i # Copyright (c) 2026 Zededa, Inc.' -e '1i # SPDX-License-Identifier: Apache-2.0' \
    -e 's/^        env:$/        env:\n        - name: KV_IO_EXTRA_ENV_VIRT_IN_CONTAINER\n          value: "true"/' /etc/kubevirt-operator.yaml
RUN echo 'c8f600c2cd6679644c6c217f03265835e014ce3ade1b79e293a94415acfbf925 /etc/kubevirt-operator.yaml' | sha256sum -c
COPY kubevirt-features.yaml /etc
COPY external-boot-image.tar /etc/

# Longhorn config
COPY lh-cfg-v1.9.1.yaml /etc/
COPY iscsid.conf /etc/iscsi/
COPY longhorn-generate-support-bundle.sh /usr/bin/
COPY longhorn-snapshot-overhead.sh /usr/bin/
COPY nsmounter /usr/bin/
COPY longhorn_uninstall_settings.yaml /etc/
COPY failover-events.sh /usr/bin/
COPY cfg-manifests/longhorn-cfg.yaml /etc/

# descheduler
COPY descheduler_rbac.yaml /etc/
COPY descheduler-policy-configmap.yaml /etc/

# ACE
# https://ranchermanager.docs.rancher.com/how-to-guides/new-user-guides/kubernetes-clusters-in-rancher-setup/register-existing-clusters
COPY kube-api-authn-webhook.yaml /etc

# Containerd config
RUN mkdir -p /etc/containerd
COPY config-k3s.toml /etc/containerd/
WORKDIR /

# Kube-VIP
COPY kubevip-sa.yaml /etc/
COPY kubevip-ds.yaml /etc/
COPY kubevip-apply.sh /usr/bin/
COPY kubevip-delete.sh /usr/bin/
RUN chmod +x /usr/bin/kubevip-apply.sh /usr/bin/kubevip-delete.sh

# nvidia-container-runtime config
RUN mkdir -p /etc/nvidia-container-runtime
COPY nvidia-container-runtime/config.toml /etc/nvidia-container-runtime
COPY nvidia-container-runtime/nvidia-device-plugin-18.0.yml \
     nvidia-container-runtime/nvidia-device-plugin-18.0-dgpu.yml /etc/k3s-manifests/

COPY sriov/sriov-device-plugin.yaml /etc/k3s-manifests/

ARG TARGETARCH

# k3s install + config happens at container start, inside kube-init.
# k3s-control is the operator alias set (k3s-start / k3s-stop /
# k3s-status); it just shells into k3s-sctl, which talks to the
# daemon's control socket.
COPY k3s-control.sh /usr/bin/k3s-control
RUN chmod +x /usr/bin/k3s-control /usr/bin/k3s-sctl && \
    ln -s /usr/bin/k3s-control /usr/bin/k3s-stop && \
    ln -s /usr/bin/k3s-control /usr/bin/k3s-start && \
    ln -s /usr/bin/k3s-control /usr/bin/k3s-status

ENTRYPOINT []
CMD ["/usr/bin/kube-init"]

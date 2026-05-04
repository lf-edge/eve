# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

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

FROM lfedge/eve-alpine:325b12087b386811fdb9d3c0adffa5fb94a34b95 AS build

ARG TARGETARCH
ENV PKGS alpine-baselayout musl-utils iproute2 iptables curl openrc \
         open-iscsi libvirt libvirt-client util-linux grep findutils jq \
         cni-plugins nfs-utils inotify-tools
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

# Note: virtctl itself is downloaded and installed in the final scratch stage below;
# the APK DB entry is added here in the build stage so it propagates via COPY /out/.
# Keep this version aligned with VIRTCTL_VERSION in the final stage.
ENV VIRTCTL_VERSION=v1.7.3
# Register virtctl in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n virtctl -v "${VIRTCTL_VERSION}" -l Apache-2.0 -u https://github.com/kubevirt/kubevirt

COPY eve-bridge /plugins/eve-bridge
WORKDIR /plugins/eve-bridge
RUN GO111MODULE=on CGO_ENABLED=0 go build -v -ldflags "-s -w" -mod=vendor -o /out/usr/bin/eve-bridge .

COPY cert-gen /plugins/cert-gen
WORKDIR /plugins/cert-gen
RUN GO111MODULE=on CGO_ENABLED=0 go build -v -ldflags "-s -w" -o /out/usr/bin/cert-gen .

COPY update-component /plugins/update-component
WORKDIR /plugins/update-component
RUN GO111MODULE=on go build -v -ldflags "-s -w" -mod=vendor -o /out/usr/bin/update-component .

FROM scratch
COPY --from=build /out/ /
RUN mkdir -p /usr/bin/kube/

# Kube general path for all manifests before applying to each cluster mode
RUN mkdir -p /etc/kube/
COPY cluster-init.sh /usr/bin/
COPY cluster-utils.sh /usr/bin/
COPY cgconfig.conf /etc
COPY utils.sh /usr/bin/
COPY pubsub.sh /usr/bin/
COPY tie-breaker-utils.sh /usr/bin/
COPY lib/* /usr/bin/
RUN mkdir -p /etc/k3s-manifests
COPY manifests/* /etc/k3s-manifests/


# upgrades
COPY cluster-update.sh /usr/bin/
COPY update-component/expected_versions.yaml /etc/
COPY update-component/settings_longhorn.yaml /etc/

# k3s
RUN mkdir -p /etc/rancher/k3s
COPY config.yaml /etc/rancher/k3s
COPY debuguser-role-binding.yaml /etc/
COPY k3s-pod-logs.sh /usr/bin/
COPY registration-utils.sh /usr/bin/
COPY all-kube-events.sh /usr/bin/
COPY lib/* /usr/bin/kube/
COPY cfg-manifests/03-enc-disable-local-path.yaml /etc/kube/

# kubevirt yaml files are patched files and will be removed later, look at cluster-init.sh
COPY multus-daemonset.yaml /etc
COPY kubevirt-operator.yaml /etc
COPY kubevirt-features.yaml /etc
COPY external-boot-image.tar /etc/
COPY kubevirt-utils.sh /usr/bin/
COPY vnc-proxy.sh /usr/bin/

# Longhorn config
COPY longhorn-utils.sh /usr/bin/
COPY lh-cfg-v1.9.1.yaml /etc/
COPY iscsid.conf /etc/iscsi/
COPY longhorn-generate-support-bundle.sh /usr/bin/
COPY longhorn-snapshot-overhead.sh /usr/bin/
COPY nsmounter /usr/bin/
COPY longhorn_uninstall_settings.yaml /etc/
COPY failover-events.sh /usr/bin/
COPY cfg-manifests/longhorn-cfg.yaml /etc/

# descheduler
COPY descheduler-utils.sh /usr/bin/
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
COPY nvidia-container-runtime/nvidia-device-plugin-18.0.yml /etc/k3s-manifests/

COPY sriov/sriov-device-plugin.yaml /etc/k3s-manifests/

ARG TARGETARCH

# Actual k3s install and config happens when this container starts during EVE boot up, look at cluster-init.sh
### NOTE: the version of virtctl should match the version of kubevirt in cluster_init.sh, else PVC creation might fail due to incompatibility
COPY k3s-control.sh /usr/bin/k3s-control
RUN chmod +x /usr/bin/k3s-control && \
    ln -s /usr/bin/k3s-control /usr/bin/k3s-stop && \
    ln -s /usr/bin/k3s-control /usr/bin/k3s-start && \
    ln -s /usr/bin/k3s-control /usr/bin/k3s-status

ENV VIRTCTL_VERSION v1.7.3
ADD https://github.com/kubevirt/kubevirt/releases/download/${VIRTCTL_VERSION}/virtctl-${VIRTCTL_VERSION}-linux-${TARGETARCH} .

RUN install virtctl-${VIRTCTL_VERSION}-linux-${TARGETARCH} /usr/bin/virtctl
# We installed under /usr/bin. Remove the downloaded version
RUN rm -f ./virtctl-${VIRTCTL_VERSION}-linux-${TARGETARCH}

ENTRYPOINT []
CMD ["/usr/bin/cluster-init.sh"]

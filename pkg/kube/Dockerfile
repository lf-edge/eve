# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 as build
ENV BUILD_PKGS go
ENV PKGS alpine-baselayout musl-utils iproute2 iptables curl openrc \
         open-iscsi libvirt libvirt-client util-linux grep findutils jq \
         cni-plugins nfs-utils
RUN eve-alpine-deploy.sh

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
COPY cluster-init.sh /usr/bin/
COPY cluster-utils.sh /usr/bin/
COPY cgconfig.conf /etc
COPY utils.sh /usr/bin/

# upgrades
COPY cluster-update.sh /usr/bin/
COPY update-component/expected_versions.yaml /etc/
COPY update-component/settings_longhorn.yaml /etc/

# k3s
COPY install-etcdctl.sh /usr/bin/
RUN mkdir -p /etc/rancher/k3s
COPY config.yaml /etc/rancher/k3s
COPY debuguser-role-binding.yaml /etc/
COPY k3s-pod-logs.sh /usr/bin/
COPY registration-utils.sh /usr/bin/

# kubevirt yaml files are patched files and will be removed later, look at cluster-init.sh
COPY multus-daemonset.yaml /etc
COPY kubevirt-operator.yaml /etc
COPY kubevirt-features.yaml /etc
COPY external-boot-image.tar /etc/
COPY kubevirt-utils.sh /usr/bin/

# Longhorn config
COPY longhorn-utils.sh /usr/bin/
COPY lh-cfg-v1.6.3.yaml /etc/
COPY iscsid.conf /etc/iscsi/
COPY longhorn-generate-support-bundle.sh /usr/bin/
COPY nsmounter /usr/bin/
COPY longhorn_uninstall_settings.yaml /etc/

# descheduler
COPY descheduler-utils.sh /usr/bin/
COPY descheduler_rbac.yaml /etc/
COPY descheduler-job.yaml /etc/
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

ARG TARGETARCH

# Actual k3s install and config happens when this container starts during EVE bootup, look at cluster-init.sh
### NOTE: the version of virtctl should match the version of kubevirt in cluster_init.sh, else PVC creation might fail due to incompatibility
ENV VIRTCTL_VERSION v1.1.0
ADD https://github.com/kubevirt/kubevirt/releases/download/${VIRTCTL_VERSION}/virtctl-${VIRTCTL_VERSION}-linux-${TARGETARCH} .

RUN install virtctl-${VIRTCTL_VERSION}-linux-${TARGETARCH} /usr/bin/virtctl
# We installed under /usr/bin. Remove the downloaded version
RUN rm -f ./virtctl-${VIRTCTL_VERSION}-linux-${TARGETARCH}

ENTRYPOINT []
CMD ["/usr/bin/cluster-init.sh"]

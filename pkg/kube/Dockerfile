# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

FROM lfedge/eve-alpine:61cdbba633ac08243ee55a371c5b74d01a673784 as build
ENV BUILD_PKGS go
ENV PKGS alpine-baselayout musl-utils iproute2 iptables curl openrc \
         open-iscsi libvirt libvirt-client util-linux grep findutils jq \
         cni-plugins nfs-utils
RUN eve-alpine-deploy.sh

# Remove unused CNI plugins
RUN for plugin in bandwidth ipvlan macvlan ptp static vlan firewall sbr tuning vrf; do \
        rm /out/usr/libexec/cni/${plugin}; \
    done

COPY eve-bridge /plugins/eve-bridge
WORKDIR /plugins/eve-bridge
RUN GO111MODULE=on CGO_ENABLED=0 go build -v -ldflags "-s -w" -mod=vendor -o /out/usr/bin/eve-bridge .

COPY cert-gen /plugins/cert-gen
WORKDIR /plugins/cert-gen
RUN GO111MODULE=on CGO_ENABLED=0 go build -v -ldflags "-s -w" -o /out/usr/bin/cert-gen .

FROM scratch
COPY --from=build /out/ /
COPY cluster-init.sh /usr/bin/
COPY cgconfig.conf /etc

# k3s
COPY install-etcdctl.sh /usr/bin/
RUN mkdir -p /etc/rancher/k3s
COPY config.yaml /etc/rancher/k3s
COPY debuguser-role-binding.yaml /etc/
COPY k3s-pod-logs.sh /usr/bin/

# kubevirt yaml files are patched files and will be removed later, look at cluster-init.sh
COPY multus-daemonset.yaml /etc
COPY kubevirt-operator.yaml /etc
COPY kubevirt-features.yaml /etc
COPY external-boot-image.tar /etc/

# Longhorn config
COPY iscsid.conf /etc/iscsi/
COPY longhorn-generate-support-bundle.sh /usr/bin/
COPY nsmounter /usr/bin/

# Containerd config
RUN mkdir -p /etc/containerd
COPY config-k3s.toml /etc/containerd/
WORKDIR /

# Actual k3s install and config happens when this container starts during EVE bootup, look at cluster-init.sh
### NOTE: the version of virtctl should match the version of kubevirt in cluster_init.sh, else PVC creation might fail due to incompatibility
ENV VIRTCTL_VERSION v1.1.0
ADD https://github.com/kubevirt/kubevirt/releases/download/${VIRTCTL_VERSION}/virtctl-${VIRTCTL_VERSION}-linux-amd64 .
RUN install virtctl-${VIRTCTL_VERSION}-linux-amd64 /usr/bin/virtctl
# We installed under /usr/bin. Remove the downloaded version
RUN rm -f ./virtctl-${VIRTCTL_VERSION}-linux-amd64

ENTRYPOINT []
CMD ["/usr/bin/cluster-init.sh"]

# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

FROM lfedge/eve-alpine:a76c418ea841a1c433e0ab562653c3801f494d8e as build
ENV BUILD_PKGS go
ENV PKGS alpine-baselayout musl-utils iproute2 iptables curl openrc \
         open-iscsi libvirt libvirt-client util-linux grep findutils jq \
         cni-plugins
RUN eve-alpine-deploy.sh

# Remove unused CNI plugins
RUN for plugin in bandwidth ipvlan macvlan ptp static vlan firewall sbr tuning vrf; do \
        rm /out/usr/libexec/cni/${plugin}; \
    done

COPY eve-bridge /plugins/eve-bridge
WORKDIR /plugins/eve-bridge
RUN GO111MODULE=on CGO_ENABLED=0 go build -v -ldflags "-s -w" -mod=vendor -o /out/usr/bin/eve-bridge .

FROM scratch
COPY --from=build /out/ /
COPY cluster-init.sh /usr/bin/
COPY cgconfig.conf /etc
# kubevirt yaml files are patched files and will be removed later, look at cluster-init.sh
COPY multus-daemonset.yaml /etc
COPY kubevirt-operator.yaml /etc
COPY kubevirt-features.yaml /etc
RUN mkdir -p /etc/containerd
COPY config-k3s.toml /etc/containerd/
RUN mkdir -p /etc/rancher/k3s
COPY config.yaml /etc/rancher/k3s
COPY external-boot-image.tar /etc/
WORKDIR /

# Actual k3s install and config happens when this container starts during EVE bootup, look at cluster-init.sh
### NOTE: the following lines are commented out until the EVE partition size increases
#ENV VIRTCTL_VERSION v0.59.0
#ADD https://github.com/kubevirt/kubevirt/releases/download/${VIRTCTL_VERSION}/virtctl-${VIRTCTL_VERSION}-linux-amd64 .
#RUN install virtctl-${VIRTCTL_VERSION}-linux-amd64 /usr/bin/virtctl
# We installed under /usr/bin. Remove the downloaded version
#RUN rm -f ./virtctl-${VIRTCTL_VERSION}-linux-amd64

ENV ETCDCTL_VERSION v3.5.5
ADD https://github.com/etcd-io/etcd/releases/download/${ETCDCTL_VERSION}/etcd-${ETCDCTL_VERSION}-linux-amd64.tar.gz .
RUN tar -zxv --strip-components=1 -C /usr/local/bin  < ./etcd-${ETCDCTL_VERSION}-linux-amd64.tar.gz

ENTRYPOINT []
CMD ["/usr/bin/cluster-init.sh"]

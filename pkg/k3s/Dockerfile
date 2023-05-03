# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

FROM lfedge/eve-alpine:c5fecbf55e75b10b48a6d4a504d2d9a2e3caf1f9 as build
ENV PKGS alpine-baselayout musl-utils iproute2 iptables curl openrc \
	open-iscsi libvirt libvirt-client util-linux grep
RUN eve-alpine-deploy.sh

FROM scratch
COPY --from=build /out/ /
COPY cluster-init.sh /usr/bin/
COPY cgconfig.conf /etc
# longhorn and kubevirt yaml files are patched files and will be removed later, look at cluster-init.sh
COPY longhorn-config.yaml /etc
COPY kubevirt-operator.yaml /etc
RUN mkdir -p /etc/rancher/k3s
COPY config.yaml /etc/rancher/k3s
WORKDIR /

# We just install software and do not enable it.
# Actual config happens when this container starts during EVE bootup, look at cluster-init.sh
ENV K3S_VERSION v1.26.3+k3s1
RUN /usr/bin/curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=${K3S_VERSION} INSTALL_K3S_SKIP_ENABLE=true INSTALL_K3S_BIN_DIR=/usr/bin sh -

ENV VIRTCTL_VERSION v0.59.0
RUN wget https://github.com/kubevirt/kubevirt/releases/download/${VIRTCTL_VERSION}/virtctl-${VIRTCTL_VERSION}-linux-amd64
RUN install virtctl-${VIRTCTL_VERSION}-linux-amd64 /usr/bin/virtctl
# We installed under /usr/bin. Remove the downloaded version
RUN rm -f ./virtctl-${VIRTCTL_VERSION}-linux-amd64

ENV ETCDCTL_VERSION v3.5.5
RUN curl -sfL https://github.com/etcd-io/etcd/releases/download/${ETCDCTL_VERSION}/etcd-${ETCDCTL_VERSION}-linux-amd64.tar.gz | tar -zxv --strip-components=1 -C /usr/local/bin


ENTRYPOINT []
CMD ["/usr/bin/cluster-init.sh"]

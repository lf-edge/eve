# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

FROM lfedge/eve-alpine:57d6a8a768256bece2f03ae4fc0eedcb5bca41a6 as build
ENV PKGS alpine-baselayout musl-utils iproute2 iptables curl openrc \
         open-iscsi libvirt libvirt-client util-linux grep findutils jq
RUN eve-alpine-deploy.sh

FROM scratch
COPY --from=build /out/ /
COPY cluster-init.sh /usr/bin/
COPY cgconfig.conf /etc
# kubevirt yaml files are patched files and will be removed later, look at cluster-init.sh
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

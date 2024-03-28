# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

#FROM lfedge/eve-alpine:d812fa9bfd099088c656e031fd21c0e1a42ce872 as build
FROM lfedge/eve-alpine:2ce6af13cbeb90e4ba3fda8903172ecc064580bb as build
ENV BUILD_PKGS git go
ENV PKGS alpine-baselayout musl-utils iproute2 iptables curl openrc \
         open-iscsi libvirt libvirt-client util-linux grep cni-plugins \
         jq findutils nfs-utils
RUN eve-alpine-deploy.sh

COPY eve-bridge /plugins/eve-bridge
WORKDIR /plugins/eve-bridge
RUN GO111MODULE=on CGO_ENABLED=0 go build -v -ldflags "-s -w" -mod=vendor -o /out/eve-bridge .

FROM scratch
COPY --from=build /out/ /
COPY cluster-init.sh /usr/bin/
COPY nsmounter /usr/bin/
COPY install-etcdctl.sh /usr/bin/
COPY cgconfig.conf /etc
# kubevirt yaml files are patched files and will be removed later, look at cluster-init.sh
# TODO: avoid so many copies of the CNI plugin
RUN mv /eve-bridge /usr/bin
COPY multus-daemonset.yaml /etc
RUN mkdir -p /etc/containerd
COPY kubevirt-features.yaml /etc
COPY kubevirt-operator.yaml /etc
COPY config-k3s.toml /etc/containerd/
COPY longhorn-generate-support-bundle.sh /usr/bin/
COPY k3s-pod-logs.sh /usr/bin/
COPY debuguser-role-binding.yaml /etc/
COPY external-boot-image.tar /etc/
COPY iscsid.conf /etc/iscsi/
RUN ls -l /etc/
RUN mkdir -p /etc/rancher/k3s
COPY config.yaml /etc/rancher/k3s
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

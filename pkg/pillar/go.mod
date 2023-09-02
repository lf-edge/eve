module github.com/lf-edge/eve/pkg/pillar

go 1.20

require (
	github.com/anatol/smart.go v0.0.0-20220615232124-371056cd18c3
	github.com/bicomsystems/go-libzfs v0.4.0
	github.com/containerd/cgroups v1.0.4
	github.com/containerd/containerd v1.6.18
	github.com/containerd/typeurl v1.0.2
	github.com/cshari-zededa/eve-tpm2-tools v0.0.4
	github.com/digitalocean/go-qemu v0.0.0-20220826173844-d5f5e3ceed89
	github.com/docker/docker v20.10.24+incompatible
	github.com/eriknordmark/ipinfo v0.0.0-20230728132417-2d8f4da903d7
	github.com/fsnotify/fsnotify v1.6.0
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/golang/protobuf v1.5.3
	github.com/google/go-cmp v0.5.9
	github.com/google/go-containerregistry v0.8.0
	github.com/google/go-tpm v0.3.0
	github.com/google/gopacket v1.1.19
	github.com/gorilla/websocket v1.5.0
	github.com/grandcat/zeroconf v1.0.0
	github.com/jackwakefield/gopac v1.0.2
	github.com/jaypipes/ghw v0.8.0
	github.com/k8snetworkplumbingwg/network-attachment-definition-client v1.4.0
	github.com/lf-edge/edge-containers v0.0.0-20221025050409-93c34bebadd2
	github.com/lf-edge/eve-api/go v0.0.0-20230818142341-272fc065f4cb
	github.com/lf-edge/eve-libs v0.0.0-20230724174211-8b4b7a344f7e
	github.com/linuxkit/linuxkit/src/cmd/linuxkit v0.0.0-20220913135124-e532e7310810
	github.com/miekg/dns v1.1.41
	github.com/moby/sys/mountinfo v0.6.0
	github.com/onsi/gomega v1.27.6
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.3-0.20211202183452-c5a74bcca799
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/packetcap/go-pcap v0.0.0-20230717110547-c34843f9206d
	github.com/prometheus/procfs v0.8.0
	github.com/satori/go.uuid v1.2.1-0.20181028125025-b2ce2384e17b
	github.com/shirou/gopsutil v3.21.11+incompatible
	github.com/shjala/gostats v0.0.0-20230215094906-69a32327600f
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.2
	github.com/tatsushid/go-fastping v0.0.0-20160109021039-d7bb493dee3e
	github.com/vishvananda/netlink v1.1.1-0.20210924202909-187053b97868
	golang.org/x/crypto v0.12.0
	golang.org/x/net v0.13.0
	golang.org/x/sys v0.11.0
	google.golang.org/grpc v1.53.0
	google.golang.org/protobuf v1.30.0
	k8s.io/api v0.28.1
	k8s.io/apimachinery v0.28.1
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/metrics v0.27.4
	kubevirt.io/api v1.0.0
	kubevirt.io/client-go v1.0.0
)

require (
	cloud.google.com/go v0.107.0 // indirect
	cloud.google.com/go/compute v1.15.1 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	cloud.google.com/go/iam v0.8.0 // indirect
	cloud.google.com/go/storage v1.27.0 // indirect
	github.com/Azure/azure-pipeline-go v0.2.3 // indirect
	github.com/Azure/azure-storage-blob-go v0.15.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect
	github.com/Microsoft/go-winio v0.5.2 // indirect
	github.com/Microsoft/hcsshim v0.9.6 // indirect
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/aws/aws-sdk-go v1.44.116 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/containerd/continuity v0.3.0 // indirect
	github.com/containerd/fifo v1.0.0 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.11.4 // indirect
	github.com/containerd/ttrpc v1.1.0 // indirect
	github.com/coreos/go-systemd/v22 v22.3.2 // indirect
	github.com/coreos/prometheus-operator v0.38.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/digitalocean/go-libvirt v0.0.0-20221020193630-0d0212f5ead2 // indirect
	github.com/docker/cli v20.10.17+incompatible // indirect
	github.com/docker/distribution v2.8.2+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.6.4 // indirect
	github.com/docker/go-connections v0.4.1-0.20190612165340-fd1b1942c4d5 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-metrics v0.0.1 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/emicklei/go-restful/v3 v3.9.0 // indirect
	github.com/estesp/manifest-tool/v2 v2.0.6-0.20220728154431-89d791ab7966 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-kit/kit v0.10.0 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/godbus/dbus/v5 v5.0.6 // indirect
	github.com/gogo/googleapis v1.4.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-design/lockfree v0.0.1 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.0 // indirect
	github.com/googleapis/gax-go/v2 v2.7.0 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/imdario/mergo v0.3.15 // indirect
	github.com/jaypipes/pcidb v0.6.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/josharian/native v1.0.1-0.20221213033349-c1e37c09b531 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.15.1 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/kubernetes-csi/external-snapshotter/client/v4 v4.2.0 // indirect
	github.com/lithammer/shortuuid/v4 v4.0.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-ieproxy v0.0.1 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mdlayher/netlink v1.7.1 // indirect
	github.com/mdlayher/socket v0.4.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/signal v0.7.0 // indirect
	github.com/moby/term v0.0.0-20220808134915-39b0c02b01ae // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/opencontainers/runc v1.1.5 // indirect
	github.com/opencontainers/selinux v1.10.1 // indirect
	github.com/openshift/api v0.0.0-20230503133300-8bbcb7ca7183 // indirect
	github.com/openshift/client-go v0.0.0-20210112165513-ebc401615f47 // indirect
	github.com/openshift/custom-resource-status v1.1.2 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/sftp v1.12.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.14.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.37.0 // indirect
	github.com/robertkrimen/otto v0.0.0-20221011175642-09fc211e5ab1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/surma/gocpio v1.0.2-0.20160926205914-fcb68777e7dc // indirect
	github.com/ti-mo/conntrack v0.4.0 // indirect
	github.com/ti-mo/netfilter v0.3.1 // indirect
	github.com/tklauser/go-sysconf v0.3.11 // indirect
	github.com/tklauser/numcpus v0.6.0 // indirect
	github.com/vbatts/tar-split v0.11.2 // indirect
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/oauth2 v0.8.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/term v0.11.0 // indirect
	golang.org/x/text v0.12.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/api v0.103.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230110181048-76db0878b65f // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	howett.net/plist v0.0.0-20181124034731-591f970eefbb // indirect
	k8s.io/apiextensions-apiserver v0.26.3 // indirect
	k8s.io/klog/v2 v2.100.1 // indirect
	k8s.io/kube-openapi v0.0.0-20230717233707-2695361300d9 // indirect
	k8s.io/utils v0.0.0-20230505201702-9f6742963106 // indirect
	kubevirt.io/containerized-data-importer-api v1.57.0-alpha1 // indirect
	kubevirt.io/controller-lifecycle-operator-sdk/api v0.0.0-20220329064328-f3cc58c6ed90 // indirect
	oras.land/oras-go v1.2.0 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)

replace (
	github.com/openshift/api => github.com/openshift/api v0.0.0-20210105115604-44119421ec6b

	k8s.io/api => k8s.io/api v0.26.3
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.26.3
	k8s.io/apimachinery => k8s.io/apimachinery v0.26.3
	k8s.io/apiserver => k8s.io/apiserver v0.26.3
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.26.3
	k8s.io/client-go => k8s.io/client-go v0.26.3
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.26.3
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.26.3
	k8s.io/code-generator => k8s.io/code-generator v0.26.3
	k8s.io/component-base => k8s.io/component-base v0.26.3
	k8s.io/cri-api => k8s.io/cri-api v0.26.3
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.26.3
	k8s.io/klog => k8s.io/klog v0.4.0
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.26.3
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.26.3
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20221012153701-172d655c2280
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.26.3
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.26.3
	k8s.io/kubectl => k8s.io/kubectl v0.26.3
	k8s.io/kubelet => k8s.io/kubelet v0.26.3
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.26.3
	k8s.io/metrics => k8s.io/metrics v0.26.3
	k8s.io/node-api => k8s.io/node-api v0.26.3
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.26.3
	k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.26.3
	k8s.io/sample-controller => k8s.io/sample-controller v0.26.3
)

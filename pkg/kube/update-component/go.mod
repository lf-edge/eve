module upgrades

go 1.24.1

require (
	github.com/Masterminds/semver v1.5.0
	github.com/longhorn/longhorn-manager v1.6.1
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.29.3
	k8s.io/apimachinery v0.29.3
	k8s.io/client-go v12.0.0+incompatible
	kubevirt.io/client-go v1.2.0
)

replace (
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

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/emicklei/go-restful/v3 v3.11.0 // indirect
	github.com/go-kit/kit v0.13.0 // indirect
	github.com/go-kit/log v0.2.1 // indirect
	github.com/go-logfmt/logfmt v0.6.0 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-openapi/jsonpointer v0.20.0 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/swag v0.22.4 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/glog v1.2.4 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.1 // indirect
	github.com/imdario/mergo v0.3.16 // indirect
	github.com/jinzhu/copier v0.3.5 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/k8snetworkplumbingwg/network-attachment-definition-client v0.0.0-20191119172530-79f836b90111 // indirect
	github.com/kubernetes-csi/external-snapshotter/client/v4 v4.2.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/openshift/api v0.0.0-20230503133300-8bbcb7ca7183 // indirect
	github.com/openshift/client-go v0.0.0-20210112165513-ebc401615f47 // indirect
	github.com/openshift/custom-resource-status v1.1.2 // indirect
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.68.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/net v0.36.0 // indirect
	golang.org/x/oauth2 v0.17.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/term v0.29.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apiextensions-apiserver v0.28.1 // indirect
	k8s.io/klog/v2 v2.120.1 // indirect
	k8s.io/kube-openapi v0.0.0-20230905202853-d090da108d2f // indirect
	k8s.io/utils v0.0.0-20240502163921-fe8a2dddb1d0 // indirect
	kubevirt.io/api v0.0.0-20240305214914-ae817ad5212e // indirect
	kubevirt.io/containerized-data-importer-api v1.57.0-alpha1 // indirect
	kubevirt.io/controller-lifecycle-operator-sdk/api v0.0.0-20220329064328-f3cc58c6ed90 // indirect
	sigs.k8s.io/controller-runtime v0.16.1 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)

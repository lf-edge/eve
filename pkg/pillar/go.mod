module github.com/lf-edge/eve/pkg/pillar

go 1.12

require (
	github.com/Azure/azure-sdk-for-go v38.0.0+incompatible
	github.com/VictorLowther/godmi v0.0.0-20190311134151-270258a8252d // indirect
	github.com/appc/docker2aci v0.17.2
	github.com/appc/spec v0.8.11 // indirect
	github.com/aws/aws-sdk-go v1.27.1
	github.com/coreos/ioprogress v0.0.0-20151023204047-4637e494fd9b // indirect
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/eriknordmark/ipinfo v0.0.0-20190220084921-7ee0839158f9
	github.com/eriknordmark/netlink v0.0.0-20190912172510-3b6b45309321
	github.com/fsnotify/fsnotify v1.4.7
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/golang/protobuf v1.3.2
	github.com/google/go-cmp v0.3.0
	github.com/google/go-containerregistry v0.0.0-20200123184029-53ce695e4179
	github.com/google/go-tpm v0.1.1
	github.com/google/gopacket v1.1.16
	github.com/gorilla/websocket v1.4.0
	github.com/jackwakefield/gopac v1.0.2
	github.com/klauspost/compress v1.9.4 // indirect
	github.com/klauspost/pgzip v1.2.1 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/lf-edge/eve/api/go v0.0.0-00010101000000-000000000000
	github.com/mdlayher/raw v0.0.0-20190419142535-64193704e472 // indirect
	github.com/ochapman/godmi v0.0.0-20140902235245-2527e2081a16 // indirect
	github.com/pkg/sftp v1.10.0
	github.com/rackn/gohai v0.0.0-20190321191141-5053e7f1fa36
	github.com/robertkrimen/otto v0.0.0-20180617131154-15f95af6e78d // indirect
	github.com/satori/go.uuid v1.2.0
	github.com/shirou/gopsutil v0.0.0-20190323131628-2cbc9195c892
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	github.com/tatsushid/go-fastping v0.0.0-20160109021039-d7bb493dee3e
	github.com/vishvananda/netlink v1.0.1-0.20190823182904-a1c9a648f744 // indirect
	github.com/vishvananda/netns v0.0.0-20190625233234-7109fa855b0f // indirect
	go4.org v0.0.0-20191010144846-132d2879e1e9 // indirect
	golang.org/x/crypto v0.0.0-20191206172530-e9b2fee46413
	golang.org/x/net v0.0.0-20191004110552-13f9640d40b9
	gopkg.in/mcuadros/go-syslog.v2 v2.3.0
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
)

replace github.com/lf-edge/eve/api/go => ../../api/go

replace github.com/vishvananda/netlink/nl => github.com/eriknordmark/netlink/nl v0.0.0-20190903203740-41fa442996b8

replace github.com/vishvananda/netlink => github.com/eriknordmark/netlink v0.0.0-20190903203740-41fa442996b8

replace git.apache.org/thrift.git => github.com/apache/thrift v0.12.0

// this is because of a lower required version from github.com/appc/docker2aci . This conflicts (gently)
// with the requirements from github.com/google/go-containerregistry.
// REMOVE this as soon as docker2aci is done!
replace github.com/opencontainers/image-spec => github.com/opencontainers/image-spec v1.0.0-rc2

//Till we upstream ECDH TPM APIs
replace github.com/google/go-tpm => github.com/cshari-zededa/go-tpm v0.0.0-20200113112746-a8476c2d6eb3

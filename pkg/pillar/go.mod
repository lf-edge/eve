module github.com/lf-edge/eve/pkg/pillar

go 1.12

require (
	contrib.go.opencensus.io/exporter/ocagent v0.4.11 // indirect
	github.com/Azure/azure-sdk-for-go v11.3.0-beta+incompatible
	github.com/Azure/go-autorest v11.7.0+incompatible // indirect
	github.com/aws/aws-sdk-go v1.19.11
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/dnaeon/go-vcr v1.0.1 // indirect
	github.com/eriknordmark/ipinfo v0.0.0-20190220084921-7ee0839158f9
	github.com/eriknordmark/netlink v0.0.0-20190417195958-c63702da36e5
	github.com/fsnotify/fsnotify v1.4.7
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/golang/protobuf v1.3.1
	github.com/google/go-cmp v0.2.0
	github.com/google/go-tpm v0.1.1
	github.com/google/gopacket v1.1.16
	github.com/gorilla/websocket v1.4.0
	github.com/hashicorp/golang-lru v0.5.1 // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/lf-edge/eve/api/go v0.0.0-00010101000000-000000000000
	github.com/mdlayher/raw v0.0.0-20190419142535-64193704e472 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/pkg/sftp v1.10.0
	github.com/satori/go.uuid v0.0.0-20181028125025-b2ce2384e17b
	github.com/satori/uuid v1.2.0 // indirect
	github.com/shirou/gopsutil v0.0.0-20190323131628-2cbc9195c892
	github.com/sirupsen/logrus v1.2.0
	github.com/vishvananda/netlink v0.0.0-20190319163122-f504738125a5 // indirect
	github.com/vishvananda/netns v0.0.0-20180720170159-13995c7128cc // indirect
	golang.org/x/crypto v0.0.0-20190404164418-38d8ce5564a5
	golang.org/x/net v0.0.0-20190419010253-1f3472d942ba
	google.golang.org/api v0.3.2 // indirect
	google.golang.org/genproto v0.0.0-20190404172233-64821d5d2107 // indirect
)

replace github.com/lf-edge/eve/api/go => ../../api/go

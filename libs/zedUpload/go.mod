module github.com/lf-edge/eve/libs/zedUpload

go 1.15

require (
	cloud.google.com/go/storage v1.17.0
	github.com/Azure/azure-pipeline-go v0.2.3
	github.com/Azure/azure-storage-blob-go v0.14.0
	github.com/aws/aws-sdk-go v1.35.35
	github.com/google/go-containerregistry v0.6.0
	github.com/lf-edge/eve/libs/nettrace v0.0.0-00010101000000-000000000000
	github.com/pkg/sftp v1.12.0
	github.com/sirupsen/logrus v1.9.0
	golang.org/x/crypto v0.1.0
	golang.org/x/net v0.4.0
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f
	google.golang.org/api v0.57.0
)

replace github.com/lf-edge/eve/api/go => ../../api/go

replace github.com/lf-edge/eve/libs/nettrace => ../nettrace

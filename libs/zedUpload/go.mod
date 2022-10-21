module github.com/lf-edge/eve/libs/zedUpload

go 1.15

require (
	cloud.google.com/go/storage v1.17.0
	github.com/Azure/azure-pipeline-go v0.2.3
	github.com/Azure/azure-storage-blob-go v0.14.0
	github.com/aws/aws-sdk-go v1.35.35
	github.com/google/go-containerregistry v0.6.0
	github.com/pkg/sftp v1.12.0
	github.com/sirupsen/logrus v1.8.1
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	golang.org/x/net v0.0.0-20210805182204-aaa1db679c0d
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f
	google.golang.org/api v0.57.0
)

replace github.com/lf-edge/eve/api/go => ../../api/go

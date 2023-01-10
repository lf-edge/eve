module github.com/lf-edge/eve/tools/dockerfile-add-scanner

go 1.19

require (
	github.com/google/uuid v1.3.0
	github.com/moby/buildkit v0.10.1-0.20221108223707-a5263dd0f990
	github.com/opencontainers/image-spec v1.1.0-rc2
	github.com/sirupsen/logrus v1.9.0
	github.com/spdx/tools-golang v0.3.1-0.20221108182156-8a01147e6342
	github.com/spf13/cobra v1.6.1
)

require (
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/containerd/containerd v1.6.12 // indirect
	github.com/containerd/ttrpc v1.1.0 // indirect
	github.com/containerd/typeurl v1.0.2 // indirect
	github.com/docker/distribution v2.8.1+incompatible // indirect
	github.com/docker/docker v20.10.18+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/gogo/googleapis v1.4.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/klauspost/compress v1.15.9 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/signal v0.7.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/testify v1.8.0 // indirect
	github.com/tonistiigi/fsutil v0.0.0-20220930225714-4638ad635be5 // indirect
	golang.org/x/crypto v0.0.0-20220926161630-eccd6366d1be // indirect
	golang.org/x/net v0.0.0-20221012135044-0b7e1fb9d458 // indirect
	golang.org/x/sync v0.0.0-20220929204114-8fcdb60fdcc0 // indirect
	golang.org/x/sys v0.0.0-20220928140112-f11e5e49a4ec // indirect
	golang.org/x/term v0.0.0-20220919170432-7a66f970e087 // indirect
	golang.org/x/text v0.3.8-0.20211004125949-5bd84dd9b33b // indirect
	google.golang.org/genproto v0.0.0-20221010155953-15ba04fc1c0e // indirect
	google.golang.org/grpc v1.50.1 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gotest.tools/v3 v3.4.0 // indirect
)

// these are for the delicate dance of docker/docker, moby/moby, moby/buildkit
replace github.com/docker/docker => github.com/moby/moby v20.10.3-0.20220728162118-71cb54cec41e+incompatible

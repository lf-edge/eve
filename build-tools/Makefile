PATH := ${CURDIR}/bin:${PATH}
COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT := $(if $(shell git status --porcelain --untracked-files=no),${COMMIT_NO}-dirty,${COMMIT_NO})
BUILD_TOOLS=bin/linuxkit bin/manifest-tool
GOC=GOPATH=${CURDIR} go

%Gopkg.lock: %Gopkg.toml
	cd `dirname $@` ; GOPATH=${CURDIR} ${CURDIR}/bin/dep ensure -v

bin/linuxkit: src/linuxkit/Gopkg.lock
	cd src/linuxkit/vendor/github.com/linuxkit/linuxkit/src/cmd/linuxkit ;\
	${GOC} build -ldflags "-X github.com/linuxkit/linuxkit/src/cmd/linuxkit/version.GitCommit=${COMMIT}" -o ${CURDIR}/$@ .

bin/manifest-tool: src/manifest-tool/Gopkg.lock
	cd src/manifest-tool/vendor/github.com/estesp/manifest-tool ;\
	${GOC} build -ldflags "-X main.gitCommit=${COMMIT}" -o ${CURDIR}/$@ .

bin/dep:
	${GOC} get github.com/golang/dep/cmd/dep

all: bin/dep bin/linuxkit bin/manifest-tool

# Set path variables.
CURDIR != pwd
PATH := ${CURDIR}/bin
GOPATH := ${CURDIR}
GO != which go # XXX: Provide more precise method.

# Export some of them to subshells
export PATH
export GOPATH

GIT_COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
GIT_COMMIT := $(if $(shell git status --porcelain --untracked-files=no),${GIT_COMMIT_NO}-dirty,${GIT_COMMIT_NO})

bin/dep:
	${GO} get github.com/golang/dep/cmd/dep

%Gopkg.lock: bin/dep %Gopkg.toml
	cd `dirname $@` ; ${GOPATH}/bin/dep ensure -v

bin/linuxkit: src/linuxkit/Gopkg.lock
	cd src/linuxkit/vendor/github.com/linuxkit/linuxkit/src/cmd/linuxkit ;\
	${GO} build -ldflags "-X github.com/linuxkit/linuxkit/src/cmd/linuxkit/version.GitCommit=${GIT_COMMIT}" -o ${GOPATH}/$@ .

bin/manifest-tool: src/manifest-tool/Gopkg.lock
	cd src/manifest-tool/vendor/github.com/estesp/manifest-tool ;\
	${GO} build -ldflags "-X main.gitCommit=${GIT_COMMIT}" -o ${GOPATH}/$@ .

all: bin/linuxkit bin/manifest-tool

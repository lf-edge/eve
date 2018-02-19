.PHONY: run pkgs help

PATH := $(CURDIR)/build-tools/bin:$(PATH)
COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT := $(if $(shell git status --porcelain --untracked-files=no),${COMMIT_NO}-dirty,${COMMIT_NO})
BUILD_TOOLS=build-tools/bin/linuxkit build-tools/bin/manifest-tool
GOC=GOPATH=$(CURDIR)/build-tools go

all: help

help:
	@echo zenbuild: LinuxKit-based Xen images composer
	@echo
	@echo amd64 targets:
	@echo "   'make supermicro.iso' builds a bootable ISO"
	@echo "   'make supermicro.img' builds a bootable raw disk image"
	@echo "   'make fallback.img'   builds an image with the fallback"
	@echo "                         bootloader"
	@echo

pkgs: $(BUILD_TOOLS)
	make -C pkg

run:
	qemu-system-x86_64 --bios ./bios/OVMF.fd -m 4096 -cpu SandyBridge -serial mon:stdio -hda ./supermicro.img \
				-net nic,vlan=0 -net user,id=eth0,vlan=0,net=192.168.1.0/24,dhcpstart=192.168.1.10,hostfwd=tcp::2222-:22 \
				-net nic,vlan=1 -net user,id=eth1,vlan=1,net=192.168.2.0/24,dhcpstart=192.168.2.10

run-fallback:
	qemu-system-x86_64 --bios ./bios/OVMF.fd -m 4096 -cpu SandyBridge -serial mon:stdio -hda fallback.img \
				-net nic,vlan=0 -net user,id=eth0,vlan=0,net=192.168.1.0/24,dhcpstart=192.168.1.10,hostfwd=tcp::2222-:22 \
				-net nic,vlan=1 -net user,id=eth1,vlan=1,net=192.168.2.0/24,dhcpstart=192.168.2.10

images/%.yml: pkgs parse-pkgs.sh images/%.yml.in FORCE
	./parse-pkgs.sh $@.in > $@

supermicro.iso: images/supermicro-iso.yml
	./makeiso.sh images/supermicro-iso.yml supermicro.iso

supermicro.img: images/supermicro-img.yml
	./makeraw.sh images/supermicro-img.yml supermicro.img

rootfs.img: images/fallback.yml
	./makerootfs.sh images/fallback.yml squash rootfs.img

fallback.img: rootfs.img
	./maketestconfig.sh config.img
	tar c rootfs.img config.img | ./makeflash.sh -C $@

%Gopkg.lock: %Gopkg.toml
	cd `dirname $@` ; GOPATH=$(CURDIR)/build-tools $(CURDIR)/build-tools/bin/dep ensure -v

build-tools/bin/linuxkit: build-tools/src/linuxkit/Gopkg.lock
	cd build-tools/src/linuxkit/vendor/github.com/linuxkit/linuxkit/src/cmd/linuxkit ;\
	$(GOC) build -ldflags "-X github.com/linuxkit/linuxkit/src/cmd/linuxkit/version.GitCommit=${COMMIT}" -o $(CURDIR)/$@ .

build-tools/bin/manifest-tool: build-tools/src/manifest-tool/Gopkg.lock
	cd build-tools/src/manifest-tool/vendor/github.com/estesp/manifest-tool ;\
	$(GOC) build -ldflags "-X main.gitCommit=${COMMIT}" -o $(CURDIR)/$@ .

build-tools/bin/dep:
	$(GOC) get github.com/golang/dep/cmd/dep

.PHONY: FORCE
FORCE:

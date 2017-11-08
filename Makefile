.PHONY: run pkgs zededa-container help

all: help

help:
	@echo zenbuild: LinuxKit/moby based Xen images composer
	@echo
	@echo amd64 targets:
	@echo "   'make supermicro.iso' builds a bootable ISO"
	@echo "   'make supermicro.img' builds a bootable raw disk image"


pkgs:
	make -C pkg

run:
	qemu-system-x86_64 --bios ./bios/OVMF.fd -m 4096 -cpu SandyBridge -serial mon:stdio -hda ./supermicro.img -redir tcp:2222::22

zededa-container/Dockerfile: pkgs parse-pkgs.sh zededa-container/Dockerfile.template
	./parse-pkgs.sh zededa-container/Dockerfile.template > zededa-container/Dockerfile

zededa-container: zededa-container/Dockerfile
	linuxkit pkg build --disable-content-trust zededa-container/

.PHONY: images/supermicro-iso.yml
images/supermicro-iso.yml: parse-pkgs.sh images/supermicro-iso.template
	./parse-pkgs.sh images/supermicro-iso.template > images/supermicro-iso.yml

supermicro.iso: zededa-container images/supermicro-iso.yml
	./makeiso.sh images/supermicro-iso.yml supermicro.iso

.PHONY: images/supermicro-img.yml
images/supermicro-img.yml: parse-pkgs.sh images/supermicro-img.template
	./parse-pkgs.sh images/supermicro-img.template > images/supermicro-img.yml

supermicro.img: zededa-container images/supermicro-img.yml
	./makeraw.sh images/supermicro-img.yml supermicro.img

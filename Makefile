.PHONY: pkgs zededa-container

all: supermicro.iso

pkgs:
	make -C pkg

zededa-container/Dockerfile: pkgs
	./parse-pkgs.sh zededa-container/Dockerfile.template > zededa-container/Dockerfile

zededa-container: zededa-container/Dockerfile
	linuxkit pkg build --disable-content-trust zededa-container/

images/supermicro-iso.yml: parse-pkgs.sh images/supermicro-iso.template
	./parse-pkgs.sh images/supermicro-iso.template > images/supermicro-iso.yml

supermicro.iso: zededa-container images/supermicro-iso.yml
	./makeiso.sh images/supermicro-iso.yml supermicro.iso

images/supermicro-img.yml: parse-pkgs.sh images/supermicro-img.template
	./parse-pkgs.sh images/supermicro-img.template > images/supermicro-img.yml

supermicro.img: zededa-container images/supermicro-img.yml
	./makeraw.sh images/supermicro-img.yml supermicro.img

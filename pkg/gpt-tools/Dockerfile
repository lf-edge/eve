# derived from Alpine 3.8
FROM linuxkit/alpine:4d13c6209a679fc7c4e850f144b7aef879914d01 as build

ENV POPT_VERSION 1.16
ENV GPTFDISK_VERSION 1.0.3
ENV VBOOT_REPO https://chromium.googlesource.com/chromiumos/platform/vboot_reference
ENV VBOOT_COMMIT e0b3841863281a3fc3b188bfbab55d401fabdc73

RUN apk add --no-cache \
    gcc \
    make \
    patch \
    libc-dev \
    util-linux-dev \
    linux-headers \
    openssl-dev \
    g++ \
    tar

RUN mkdir /out

#
# Step 1: Install SGDISK
#

WORKDIR /
RUN mkdir /popt
COPY popt-${POPT_VERSION}.tar.gz /popt

WORKDIR /popt
RUN tar xvzf popt-${POPT_VERSION}.tar.gz
WORKDIR /popt/popt-${POPT_VERSION}
COPY patches/popt* /popt
RUN for patch in /popt/*patch ; do patch -p1 < $patch ; done
RUN ./configure && make && make install


WORKDIR /
RUN mkdir -p /sgdisk/patches 
COPY gptfdisk-${GPTFDISK_VERSION}.tar.gz /sgdisk
COPY patches/* /sgdisk/patches/

WORKDIR /sgdisk
RUN tar xvzf gptfdisk-${GPTFDISK_VERSION}.tar.gz

WORKDIR /sgdisk/gptfdisk-${GPTFDISK_VERSION}
RUN set -e && for patch in ../patches/sgdisk-*.patch; do \
        echo "Applying $patch"; \
        patch -p1 < "$patch"; \
    done
RUN make LDFLAGS=-static sgdisk
RUN cp sgdisk /out/sgdisk


#
# Step 2: Fetch and compile CGPT
#

WORKDIR /
COPY vboot_reference-${VBOOT_COMMIT}.tar.gz /
RUN tar xvzf vboot_reference-${VBOOT_COMMIT}.tar.gz

WORKDIR /vboot_reference
RUN make cgpt LDFLAGS=-static
RUN cp build/cgpt/cgpt /out/cgpt

FROM scratch
COPY --from=build /out/sgdisk /usr/bin/sgdisk
COPY --from=build /out/cgpt /usr/bin/cgpt
COPY files/zboot /usr/bin/zboot

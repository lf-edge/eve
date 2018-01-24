FROM alpine:3.6 as build

ENV POPT_VERSION 1.16
ENV GPTFDISK_VERSION 1.0.3

RUN apk add --no-cache \
    gcc \
    make \
    patch \
    libc-dev \
    popt \
    popt-dev \
    util-linux-dev \
    linux-headers \
    g++ \
    tar

RUN mkdir /out

#
# Step 1: Install libpopt, we need it as alpine
#         does not install a static library

#http://rpm5.org/files/popt/popt-1.16.tar.gz
WORKDIR /
RUN mkdir /popt
COPY popt-${POPT_VERSION}.tar.gz /popt

WORKDIR /popt
RUN tar xvzf popt-${POPT_VERSION}.tar.gz
WORKDIR /popt/popt-${POPT_VERSION}
RUN ./configure && make && make install


WORKDIR /
RUN mkdir -p /sgdisk/patches 
COPY gptfdisk-${GPTFDISK_VERSION}.tar.gz /sgdisk
COPY patches/* /sgdisk/patches/

WORKDIR /sgdisk
RUN tar xvzf gptfdisk-${GPTFDISK_VERSION}.tar.gz

WORKDIR /sgdisk/gptfdisk-${GPTFDISK_VERSION}
RUN set -e && for patch in ../patches/*.patch; do \
        echo "Applying $patch"; \
        patch -p1 < "$patch"; \
    done
RUN make LDFLAGS=-static sgdisk
RUN cp sgdisk /out/sgdisk

FROM scratch
COPY --from=build /out/sgdisk /usr/bin/sgdisk
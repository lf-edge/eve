FROM ubuntu:20.04 as sdk-builder

ENV DEBIAN_FRONTEND noninteractive

# hadolint ignore=DL3008,DL3015
RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    build-essential \
    cmake \
    curl \
    debhelper \
    git \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    libssl-dev \
    libtool \
    lsb-release \
    ocaml \
    ocamlbuild \
    protobuf-compiler \
    python \
    reprepro \
    wget \
    unzip


RUN git clone https://github.com/intel/linux-sgx
WORKDIR /linux-sgx
RUN git checkout sgx_2.17.1 && \
    make preparation && \
    cp external/toolset/ubuntu20.04/* /usr/local/bin && \
    make -j "$(getconf _NPROCESSORS_ONLN)" sdk_install_pkg

WORKDIR /opt/intel
RUN sh -c 'echo yes | /linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_*.bin'

WORKDIR /linux-sgx
RUN make -j "$(getconf _NPROCESSORS_ONLN)" psw_install_pkg


FROM ubuntu:20.04 as app-builder

ENV DEBIAN_FRONTEND noninteractive

# hadolint ignore=DL3008,DL3015
RUN apt-get update && apt-get install -y \
    g++ \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    libssl-dev \
    make

WORKDIR /opt/intel
COPY --from=sdk-builder /linux-sgx/linux/installer/bin/*.bin ./
RUN mkdir /etc/init && \
    sh -c './sgx_linux_x64_psw*.bin' && \
    sh -c 'echo yes | ./sgx_linux_x64_sdk_*.bin'

WORKDIR /opt/intel/sgxpsw/aesm
RUN ln -s libsgx_pce_logic.so libsgx_pce_logic.so.1

COPY app /app
WORKDIR /app
RUN SGX_DEBUG=0 SGX_MODE=HW SGX_PRERELEASE=1 make && \
    make DESTDIR=/out/app install


FROM ubuntu:20.04 as final_amd64

ENV DEBIAN_FRONTEND noninteractive

# hadolint ignore=DL3008,DL3015
RUN apt-get update && apt-get install -y \
    libssl1.1 \
    libprotobuf17 \
    libcurl4 &&\
    rm -rf /var/lib/apt/lists/*

COPY --from=app-builder /out/app /app
COPY --from=app-builder /opt/intel/sgxpsw/aesm /opt/intel/sgxpsw/aesm
COPY --from=app-builder /etc/aesmd.conf /etc/aesmd.conf
COPY --from=app-builder /usr/lib/libsgx_* /usr/lib/

# dummy image for arm64
FROM ubuntu:20.04 as final_arm64

# hadolint ignore=DL3006
FROM final_${TARGETARCH}

COPY entrypoint.sh /

ENTRYPOINT []
CMD ["/entrypoint.sh"]

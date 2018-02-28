FROM alpine:3.6 as build

RUN apk add --no-cache \
    automake \
    autoconf \
    gettext \
    gettext-dev \
    git \
    pkgconfig \
    libtool \
    libc-dev \
    linux-headers \
    gcc \
    make \
    cmake

WORKDIR /
RUN git clone https://git.openwrt.org/project/uqmi.git
RUN git clone https://git.openwrt.org/project/libubox.git
RUN git clone https://github.com/json-c/json-c.git

WORKDIR /json-c
RUN ./autogen.sh && ./configure && make install

WORKDIR /libubox
RUN cmake . -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF && make install

WORKDIR /uqmi
RUN cmake -DBUILD_STATIC=true . && make

# second stage (new-ish Docker feature) for smaller image
FROM alpine:3.6 

RUN apk add --no-cache ppp

ENTRYPOINT []
WORKDIR /
COPY --from=build /uqmi/uqmi /bin
COPY usr/ /usr/
COPY etc/ /etc/
CMD ["/usr/bin/wwan-init.sh"]

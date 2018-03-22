FROM alpine:3.6 as build

RUN apk add --no-cache \
    alpine-sdk

# Aports user setup
RUN adduser -D zbuild
RUN mkdir -p /var/cache/distfiles
RUN chgrp abuild /var/cache/distfiles
RUN chmod g+w /var/cache/distfiles
RUN addgroup zbuild abuild
USER zbuild
WORKDIR /home/zbuild

# Pull aports
RUN git config --global user.name "Zededa Alpine Packaging Team"
RUN git config --global user.email "opensource@zededa.com"
RUN git clone git://git.alpinelinux.org/aports
RUN abuild-keygen -a -i



FROM ZTOOLS_TAG as zededa

FROM linuxkit/alpine:77287352db68b442534c0005edd6ff750c8189f3
RUN apk add --no-cache \
  mtools \
  dosfstools
ADD make-config /

#
# Copy Configuration
#

# Copy ztools conf
COPY --from=zededa /opt/zededa/examples/config /conf/

WORKDIR /
ENTRYPOINT [ "/make-config" ]

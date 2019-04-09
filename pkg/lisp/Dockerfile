FROM alpine:3.8 AS lisp
ENV LISP_VERSION=release-0.488

ADD https://github.com/farinacci/lispers.net/archive/${LISP_VERSION}.tar.gz /tmp/
ADD patches /tmp/patches

RUN apk add --no-cache py2-pyflakes py2-pip gcc linux-headers  \
    libc-dev python python-dev libffi-dev openssl-dev libpcap-dev
RUN ln -s pyflakes-2 /usr/bin/pyflakes
RUN tar -C /tmp -xzvf /tmp/${LISP_VERSION}.tar.gz && \
    cd /tmp/lispers.net-${LISP_VERSION} && \
    for p in /tmp/patches/* ; do patch -p1 < $p ; done && \
    cd build ; python make-release.py dev && \
    mkdir /lisp ; tar -C /lisp -xzvf latest/lispers.net.tgz

RUN pip install --upgrade pip && pip install -r /lisp/pip-requirements.txt
RUN apk del py2-pip py2-pyflakes

# Putting it all together
FROM scratch

COPY --from=lisp /lisp /opt/zededa/lisp/
COPY --from=lisp /usr/bin/pydoc /usr/bin/smtpd.py /usr/bin/
COPY --from=lisp /usr/lib/python2.7/site-packages /usr/lib/python2.7/site-packages 

ADD rootfs/ /

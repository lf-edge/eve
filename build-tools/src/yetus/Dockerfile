FROM apache/yetus:master
ENV CGO_ENABLED=1
ENV GO111MODULE=on
ENV CGO_LDFLAGS=-lm
ENV YETUS_OUT=/tmp/yetus-out
RUN apt-get -q update && apt-get -q install --no-install-recommends -y libpcap-dev
RUN go get github.com/golangci/golangci-lint/cmd/golangci-lint@692dacb773b703162c091c2d8c59f9cd2d6801db && mv /root/go/bin/golangci-lint /usr/local/bin
RUN mkdir -p ${YETUS_OUT}
RUN echo "bootstrap" > ${YETUS_OUT}/bootstrap
WORKDIR /src

CMD test-patch \
      --build-tool=nobuild \
      --plugins=all,-asflicense,-shelldocs,-gitlab \
      --patch-dir=${YETUS_OUT} \
      --whitespace-tabs-ignore-list='.*Makefile.*','.*\.go','.*\.dts','.*\.md' \
      --html-report-file=${YETUS_OUT}/report.html \
      --console-report-file=${YETUS_OUT}/console.txt \
      --brief-report-file=${YETUS_OUT}/brief.txt \
      --excludes=.yetus-excludes \
      --ignore-unknown-options=true \
      --revive-config=.revive.toml \
      --linecomments='' \
      --bugcomments=briefreport,htmlout,junit \
      --junit-results-xml=${YETUS_OUT}/results.xml \
      --tests-filter=checkmake,golang,golangcilint \
      --continuous-improvement=true
    


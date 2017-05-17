#!/bin/bash
while /bin/true; do openssl ocsp -index /home/nordmark/CA/index.txt -port 80 -rsigner root/ocsp01.priv.sc.zededa.net.cert.pem -rkey root/ocsp01.priv.sc.zededa.net.key.pem -CA root/intermediate.cert.pem -text -out /tmp/log.txt -nmin 10; done



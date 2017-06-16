Create onboarding certificates. Register different ones under different names (to get different IIDs).

e.g.
./generate-onboard.sh /tmp/nordmark/app1.onboard
./register app1.erik@zededa.com /tmp/`whoami`/app1.onboard.cert.pem 10
./generate-onboard.sh /tmp/nordmark/app2.onboard
./register app2.erik@zededa.com /tmp/`whoami`/app2.onboard.cert.pem 10

On device, put above in ~/onboard
app1 and app3 in one iid.
app2 and app4 in a different iid.

cd ~onboard/
mkdir app1
cp app1.onboard.cert.pem app1/onboard.cert.pem
cp app1.onboard.key.pem app1/onboard.key.pem
mkdir app2
cp app2.onboard.cert.pem app2/onboard.cert.pem
cp app2.onboard.key.pem app2/onboard.key.pem

mkdir app3
cp app1.onboard.cert.pem app3/onboard.cert.pem
cp app1.onboard.key.pem app3/onboard.key.pem
mkdir app4
cp app2.onboard.cert.pem app4/onboard.cert.pem
cp app2.onboard.key.pem app4/onboard.key.pem

cp -p /usr/local/etc/zededa/{lisp.config.zed,server,root-certificate.pem} app1
cp -p /usr/local/etc/zededa/{lisp.config.zed,server,root-certificate.pem} app2
cp -p /usr/local/etc/zededa/{lisp.config.zed,server,root-certificate.pem} app3
cp -p /usr/local/etc/zededa/{lisp.config.zed,server,root-certificate.pem} app4

sudo /usr/local/bin/zededa/generate-device.sh app1/device
sudo /usr/local/bin/zededa/generate-device.sh app2/device
sudo /usr/local/bin/zededa/generate-device.sh app3/device
sudo /usr/local/bin/zededa/generate-device.sh app4/device

/usr/local/bin/zededa/client app1 selfRegister
/usr/local/bin/zededa/client app2 selfRegister
/usr/local/bin/zededa/client app1 lookupParam
/usr/local/bin/zededa/client app2 lookupParam

/usr/local/bin/zededa/client app3 selfRegister
/usr/local/bin/zededa/client app3 lookupParam
/usr/local/bin/zededa/client app4 selfRegister
/usr/local/bin/zededa/client app4 lookupParam

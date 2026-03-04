
#!/bin/bash
#
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# This is a helper script to prepare a software TPM environment
# for running TPM related tests in CI.


CWD=$(pwd)
TPM_SRV_PORT=1337
TPM_CTR_PORT=$((TPM_SRV_PORT + 1))
EK_HANDLE=0x81000001
SRK_HANDLE=0x81000002
AIK_HANDLE=0x81000003
QUOTE_KEY_HANDLE=0x81000004
ECDH_HANDLE=0x81000005
DEVICE_KEY_HANDLE=0x817FFFFF
EK_CERT_HANDLE=0x01C00002
EVE_TPM_STATE=/tmp/eve-tpm
EVE_TPM_CTRL="$EVE_TPM_STATE/ctrl.sock"
# this path is hardcoded in the pkg/pillar/evetpm/testhelper.go, so if you change
# it here, change it there too.
EVE_TPM_SRV="$EVE_TPM_STATE/srv.sock"

echo "[+] Installing swtpm and tpm2-tools ..."
sudo apt-get -qq update -y > /dev/null
sudo apt-get install openssl curl swtpm tpm2-tools -y -qq > /dev/null

echo "[+] Installing zfs (pillar dependency)..."
ZFS_URL="https://github.com/openzfs/zfs/archive/refs/tags/zfs-2.3.3.tar.gz"
mkdir -p /tmp/zfs
cd /tmp/zfs
curl -s -LO $ZFS_URL > /dev/null
tar -xf zfs-2.3.3.tar.gz --strip-components=1 > /dev/null
./autogen.sh > /dev/null 2>&1
./configure \
  --prefix=/usr \
  --with-tirpc \
  --sysconfdir=/etc \
  --mandir=/usr/share/man \
  --infodir=/usr/share/info \
  --localstatedir=/var \
  --with-config=user \
  --with-udevdir=/lib/udev \
  --disable-systemd \
  --disable-static > /dev/null 2>&1
./scripts/make_gitrev.sh > /dev/null 2>&1
make -j "$(getconf _NPROCESSORS_ONLN)" > /dev/null 2>&1
sudo make install-strip > /dev/null 2>&1

echo "[+] preparing the environment ..."
rm -rf $EVE_TPM_STATE
mkdir -p $EVE_TPM_STATE

flushtpm() {
  tpm2 flushcontext -t
  tpm2 flushcontext -l
  tpm2 flushcontext -s
}

swtpm socket --tpm2 \
    --server port="$TPM_SRV_PORT" \
    --ctrl type=tcp,port="$TPM_CTR_PORT" \
    --tpmstate dir="$EVE_TPM_STATE" \
    --flags startup-clear &

PID=$!

# Set Transmission Interface (TCTI) to swtpm tcp socket, so tpm2-tools use it
# instead of the default char device interface.
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=$TPM_SRV_PORT"

# start fresh
tpm2 clear

# The ek, srk and aik are created here based on what we do in createOtherKeys
# in pkg/pillar/cmd/tpmmgr/tpmmgr.go.
# create Endorsement Key
tpm2 createprimary -C e -G rsa2048:aes128cfb -g sha256 -c ek.ctx \
  -a 'fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|restricted|decrypt|userwithauth'

# this setup is fragile because we are not using a resource manager,
# so flush everything to be safe to not face "out of memory for object contexts" errors.
flushtpm

# create srk
tpm2 createprimary -C o -G rsa2048:aes128cfb -g sha256 -c srk.ctx \
                   -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth'
flushtpm

# create aik
tpm2 createprimary -C o -G rsa:rsassa-sha256:null -g sha256 -c aik.ctx \
                   -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign|noda'
flushtpm

# create quote key (same as aik but at different handle for attestation)
tpm2 createprimary -C o -G rsa:rsassa-sha256:null -g sha256 -c quotekey.ctx \
                   -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign|noda'
flushtpm

# create ecdh key
tpm2 createprimary -C o -G ecc256:ecdh-sha256 -c ecdh.ctx \
                   -a 'noda|decrypt|sensitivedataorigin|userwithauth'
flushtpm

# create device key (used for device certificate and EncryptDecryptUsingTpm)
tpm2 createprimary -C o -G ecc256 -g sha256 -c device.ctx \
                   -a 'sign|noda|decrypt|sensitivedataorigin|userwithauth'
flushtpm

# create and store a self signed EK certificate in NV index
openssl genrsa -out ek_temp.key 2048 2>/dev/null
openssl req -new -x509 -key ek_temp.key \
        -out ek_cert.pem -days 3650 \
        -subj "/CN=TPM Endorsement Key" 2>/dev/null


# store it
openssl x509 -in ek_cert.pem -outform DER -out ek_cert.der 2>/dev/null
EK_CERT_SIZE=$(wc -c < ek_cert.der)
tpm2 nvdefine $EK_CERT_HANDLE -C o -s $EK_CERT_SIZE \
    -a "ownerread|ownerwrite|authread|policywrite|ppwrite" 2>/dev/null || true
tpm2 nvwrite $EK_CERT_HANDLE -C o -i ek_cert.der 2>/dev/null
flushtpm

# make persisted know-good-handles out of ek, srk, aik, quotekey, ecdh and device keys.
tpm2 evictcontrol -C o -c ek.ctx $EK_HANDLE;flushtpm
tpm2 evictcontrol -C o -c srk.ctx $SRK_HANDLE;flushtpm
tpm2 evictcontrol -C o -c aik.ctx $AIK_HANDLE;flushtpm
tpm2 evictcontrol -C o -c quotekey.ctx $QUOTE_KEY_HANDLE;flushtpm
tpm2 evictcontrol -C o -c ecdh.ctx $ECDH_HANDLE;flushtpm
tpm2 evictcontrol -C o -c device.ctx $DEVICE_KEY_HANDLE;flushtpm

# create device certificate (required by EncryptDecryptUsingTpm)
# The EncryptDecryptUsingTpm function only needs to extract the ECC public key
# from the certificate, so for testing we create a simple self-signed cert.
openssl ecparam -genkey -name prime256v1 -out "$EVE_TPM_STATE/device.key.pem" 2>/dev/null
openssl req -new -x509 -key "$EVE_TPM_STATE/device.key.pem" \
        -out "$EVE_TPM_STATE/device.cert.pem" \
        -days 3650 -subj "/O=The Linux Foundation/CN=EVE" \
        -set_serial 1 2>/dev/null

# Create ECDH certificate signed by device certificate
# We use a temporary key for CSR, but force the public key to be the TPM's ECDH key
tpm2 readpublic -c $ECDH_HANDLE -f pem -o "$EVE_TPM_STATE/ecdh.pub.pem" 2>/dev/null
openssl ecparam -genkey -name prime256v1 -out "$EVE_TPM_STATE/temp_ecdh.key" 2>/dev/null
openssl req -new -key "$EVE_TPM_STATE/temp_ecdh.key" \
    -subj "/CN=Device ECDH certificate" \
    -out "$EVE_TPM_STATE/ecdh.csr" 2>/dev/null

openssl x509 -req -in "$EVE_TPM_STATE/ecdh.csr" \
    -CA "$EVE_TPM_STATE/device.cert.pem" \
    -CAkey "$EVE_TPM_STATE/device.key.pem" \
    -CAcreateserial \
    -out "$EVE_TPM_STATE/ecdh.cert.pem" \
    -days 365 \
    -force_pubkey "$EVE_TPM_STATE/ecdh.pub.pem" 2>/dev/null

# Clean up temps
rm "$EVE_TPM_STATE/temp_ecdh.key" "$EVE_TPM_STATE/ecdh.csr" "$EVE_TPM_STATE/ecdh.pub.pem"

# clean up
rm -f ek.ctx srk.ctx aik.ctx quotekey.ctx ecdh.ctx device.ctx ek_temp.key ek_cert.pem ek_cert.der

# kill swtpm, we are going to start it again with unix sockets
kill $PID

echo "========================================================"
echo "[+] TPM setup done."
echo "========================================================"

# start swtpm again, but this time with unix sockets for tests to use.
# in case we need to debug this, cat the log file.
swtpm socket --tpm2 \
    --flags startup-clear \
    --server type=unixio,path="$EVE_TPM_SRV" \
    --ctrl type=unixio,path="$EVE_TPM_CTRL" \
    --tpmstate dir="$EVE_TPM_STATE" \
    --log file="$EVE_TPM_STATE/swtpm.log" &

PID=$!

# copy test data, so it is accessible from the go tests
cp "$CWD/tests/tpm/testdata/binary_bios_measurement" $EVE_TPM_STATE
cp "$CWD/tests/tpm/testdata/measurefs_tpm_event_log" $EVE_TPM_STATE
cp "$CWD/tests/tpm/testdata/ec_key_leading_zero.pem" $EVE_TPM_STATE
openssl req -new -x509 -key "$EVE_TPM_STATE/ec_key_leading_zero.pem" \
        -out "$EVE_TPM_STATE/ec_key_leading_zero.cert" \
        -days 1337 -subj "/CN=ECDH Test Key With Leading Zero/"

# give swtpm time to start and init the TPM
sleep 1

# run tests
echo "[+] Running tests ..."
echo "========================================================"

# we dont have many test that require the TPM, so hardcode test paths here.
cd "$CWD/pkg/pillar/evetpm" && go test -v -coverprofile="evetpm.coverage.txt" -covermode=atomic
cd "$CWD/pkg/pillar/cmd/msrv" && go test -v -test.run ^TestTpmActivateCred$ -coverprofile="actcred.coverage.txt" -covermode=atomic
cd "$CWD/pkg/pillar/cmd/vcomlink" && go test -v -coverprofile="vcomlink.coverage.txt" -covermode=atomic

# we are done, kill the swtpm
kill $PID

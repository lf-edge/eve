
#!/bin/bash
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
set -e

CWD=$(pwd)

SNIFF=0
for arg in "$@"; do
    case "$arg" in
        -sniff) SNIFF=1 ;;
    esac
done

TPM_SRV_PORT=1337
TPM_CTR_PORT=$((TPM_SRV_PORT + 1))
EK_HANDLE=0x81000001
SRK_HANDLE=0x81000002
AIK_HANDLE=0x81000003
ECDH_HANDLE=0x81000005
EVE_TPM_STATE=/tmp/eve-tpm
EVE_TPM_CTRL="$EVE_TPM_STATE/ctrl.sock"
# this path is hardcoded in the pkg/pillar/evetpm/testhelper.go, so if you change
# it here, change it there too.
EVE_TPM_SRV="$EVE_TPM_STATE/srv.sock"

echo "[+] Installing build dependencies and tpm2-tools ..."
export DEBIAN_FRONTEND=noninteractive
sudo -E apt-get -qq update -y > /dev/null
sudo -E apt-get install -y -qq -o Dpkg::Options::="--force-confdef" \
    curl git tpm2-tools automake autoconf autoconf-archive libtool \
    build-essential libssl-dev libgnutls28-dev gnutls-bin libtasn1-dev \
    libjson-glib-dev libjson-c-dev libseccomp-dev expect gawk net-tools \
    socat libtirpc-dev > /dev/null

# Purge distro ZFS and libtpms so their libraries can't shadow the versions we
# build from source below.
sudo -E apt-get remove -y -qq --purge 'libtpms*' 'libzfs*' 'libnvpair*' \
    'libzpool*' 'libzfslinux*' 'zfs*' > /dev/null 2>&1 || true

# Build libtpms, same version as pkg/vtpm/Dockerfile
echo "[+] Building libtpms v0.10.0 from source ..."
LIBTPMS_BUILD=$(mktemp -d)
git clone --branch v0.10.0 --depth 1 https://github.com/stefanberger/libtpms.git "$LIBTPMS_BUILD"
cd "$LIBTPMS_BUILD"
./autogen.sh --prefix=/usr --with-tpm2 > /dev/null
make -j "$(getconf _NPROCESSORS_ONLN)" > /dev/null
sudo make install > /dev/null
sudo ldconfig

# Build swtpm from the same commit as pkg/vtpm/Dockerfile
echo "[+] Building swtpm from source (commit 732bbd6) ..."
SWTPM_BUILD=$(mktemp -d)
git clone https://github.com/stefanberger/swtpm.git "$SWTPM_BUILD"
cd "$SWTPM_BUILD"
git checkout 732bbd6ad3a52b9552b5a1620e03a9f6449a1aab
./autogen.sh --prefix=/usr > /dev/null
make -j "$(getconf _NPROCESSORS_ONLN)" > /dev/null
sudo make install > /dev/null

echo "[+] Building zfs (pillar dependency)..."
ZFS_BUILD=$(mktemp -d)
ZFS_URL="https://github.com/openzfs/zfs/archive/refs/tags/zfs-2.3.3.tar.gz"
curl -sL "$ZFS_URL" | tar -xz --strip-components=1 -C "$ZFS_BUILD"
cd "$ZFS_BUILD"
./autogen.sh > /dev/null
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
  --disable-static > /dev/null
./scripts/make_gitrev.sh > /dev/null
make -j "$(getconf _NPROCESSORS_ONLN)" > /dev/null
sudo make install-strip > /dev/null
sudo ldconfig

echo "[+] preparing the environment ..."
rm -rf $EVE_TPM_STATE
mkdir -p $EVE_TPM_STATE

flushtpm() {
  tpm2 flushcontext -t
  tpm2 flushcontext -l
  tpm2 flushcontext -s
}

echo "[+] swtpm version and capabilities:"
swtpm --version
swtpm socket --tpm2 --print-capabilities
echo "========================================================"

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
#
# create Endorsement Key, use -L to set the standard EK auth policy,
# so we end up with the same EK as EVE creates.
printf '\x83\x71\x97\x67\x44\x84\xb3\xf8\x1a\x90\xcc\x8d\x46\xa5\xd7\x24\xfd\x52\xd7\x6e\x06\x52\x0b\x64\xf2\xa1\xda\x1b\x33\x14\x69\xaa' > "$EVE_TPM_STATE/ek_policy.bin"
tpm2 createprimary -C e -G rsa2048:aes128cfb -g sha256 -c ek.ctx \
    -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt' \
    -L "$EVE_TPM_STATE/ek_policy.bin"
flushtpm

# create a self-signed EK cert and store it in the standard EK cert NV index (0x01C00002)
EK_CERT_HANDLE=0x01C00002
EK_CERT_FILE="$EVE_TPM_STATE/ek_test.cert.der"
openssl req -x509 -newkey rsa:2048 -keyout "$EVE_TPM_STATE/ek_test.key" \
    -out "$EVE_TPM_STATE/ek_test.cert.pem" \
    -days 365 -nodes -subj "/CN=Test EK Cert/" 2>/dev/null
openssl x509 -in "$EVE_TPM_STATE/ek_test.cert.pem" -outform DER -out "$EK_CERT_FILE"
EK_CERT_SIZE=$(wc -c < "$EK_CERT_FILE")
tpm2 nvdefine $EK_CERT_HANDLE -C o -s "$EK_CERT_SIZE" -a "authread|ownerwrite"
tpm2 nvwrite $EK_CERT_HANDLE -C o -i "$EK_CERT_FILE"
flushtpm

# create srk
tpm2 createprimary -C o -G rsa2048:aes128cfb -g sha256 -c srk.ctx \
                   -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth'
flushtpm

# create aik
tpm2 createprimary -C o -G rsa:rsassa-sha256:null -g sha256 -c aik.ctx \
                   -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign|noda'
flushtpm

# create ecdh key
tpm2 createprimary -C o -G ecc256:ecdh-sha256 -c ecdh.ctx \
                   -a 'noda|decrypt|sensitivedataorigin|userwithauth'
flushtpm

# make persisted know-good-handles out of ek, srk, aik and ecdh keys.
tpm2 evictcontrol -C o -c ek.ctx $EK_HANDLE;flushtpm
tpm2 evictcontrol -C o -c srk.ctx $SRK_HANDLE;flushtpm
tpm2 evictcontrol -C o -c aik.ctx $AIK_HANDLE;flushtpm
tpm2 evictcontrol -C o -c ecdh.ctx $ECDH_HANDLE;flushtpm

# clean up
rm ek.ctx srk.ctx aik.ctx ecdh.ctx

# kill swtpm, we are going to start it again with unix sockets
kill $PID

# start swtpm again, but this time with unix sockets for tests to use,
# in case we need to debug this, cat the log file.
SNIFFER_PID=""
if [ "$SNIFF" -eq 1 ]; then
    # In sniff mode, swtpm listens on a separate socket and the sniffer
    # bridges EVE_TPM_SRV → srv.real.sock so tests connect transparently.
    EVE_TPM_SRV_REAL="$EVE_TPM_STATE/srv.real.sock"
    swtpm socket --tpm2 \
        --flags startup-clear \
        --server type=unixio,path="$EVE_TPM_SRV_REAL" \
        --ctrl type=unixio,path="$EVE_TPM_CTRL" \
        --tpmstate dir="$EVE_TPM_STATE" \
        --log file="$EVE_TPM_STATE/swtpm.log" &
    PID=$!
    echo "[+] Building sniffer ..."
    (cd "$CWD/tests/tpm/sniffer" && go build -buildvcs=false -o sniffer .)
    "$CWD/tests/tpm/sniffer/sniffer" \
        -real "$EVE_TPM_SRV_REAL" \
        -listen "$EVE_TPM_SRV" &
    SNIFFER_PID=$!
    echo "[+] Sniffer started (PID $SNIFFER_PID), intercepting TPM traffic on $EVE_TPM_SRV"
else
    swtpm socket --tpm2 \
        --flags startup-clear \
        --server type=unixio,path="$EVE_TPM_SRV" \
        --ctrl type=unixio,path="$EVE_TPM_CTRL" \
        --tpmstate dir="$EVE_TPM_STATE" \
        --log file="$EVE_TPM_STATE/swtpm.log" &
    PID=$!
fi

# copy test data, so it is accessible from the go tests
cp "$CWD/tests/tpm/testdata/binary_bios_measurement" $EVE_TPM_STATE
cp "$CWD/tests/tpm/testdata/measurefs_tpm_event_log" $EVE_TPM_STATE
cp "$CWD/tests/tpm/testdata/ec_key_leading_zero.pem" $EVE_TPM_STATE
openssl req -new -x509 -key "$EVE_TPM_STATE/ec_key_leading_zero.pem" \
        -out "$EVE_TPM_STATE/ec_key_leading_zero.cert" \
        -days 1337 -subj "/CN=ECDH Test Key With Leading Zero/"

# give swtpm time to start and init the TPM
sleep 1

# disable set -e so all tests run regardless of individual failures
set +e

# add any test that requires the TPM here ...
echo "[+] Running tests ..."
echo "========================================================"

FAILED=0
run_test() {
    "$@"
    local rc=$?
    if [ $rc -ne 0 ]; then
        echo "[!] FAILED: $*"
        FAILED=1
    fi
}

run_test sh -c "cd \"$CWD/pkg/pillar/evetpm\" && go test -v -coverprofile=\"evetpm.coverage.txt\" -covermode=atomic"
run_test sh -c "cd \"$CWD/pkg/pillar/cmd/msrv\" && go test -v -test.run ^TestTpmActivateCred$ -coverprofile=\"actcred.coverage.txt\" -covermode=atomic"
run_test sh -c "cd \"$CWD/pkg/pillar/cmd/vcomlink\" && go test -v -coverprofile=\"vcomlink.coverage.txt\" -covermode=atomic"
run_test sh -c "cd \"$CWD/pkg/vtpm/swtpm-vtpm\" && go test -v -test.run ^TestLaunchWithRealTPMEncryption$ ./src/ -coverprofile=\"swtpm-vtpm.coverage.txt\" -covermode=atomic"

# we are done, kill swtpm and sniffer
kill $PID
[ -n "$SNIFFER_PID" ] && kill "$SNIFFER_PID"
rm -rf $EVE_TPM_STATE

exit $FAILED

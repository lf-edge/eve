
#!/bin/bash
#
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# add more TPM tests here
TESTS=(
  "/pillar/evetpm"
  )

TPM_SRV_PORT=1337
TPM_CTR_PORT=$((TPM_SRV_PORT + 1))
ENDO_SEED=0x4000000B
EK_HANDLE=0x81000001
SRK_HANDLE=0x81000002
EVE_TPM_STATE=/tmp/eve-tpm
EVE_TPM_CTRL="$EVE_TPM_STATE/ctrl.sock"
EVE_TPM_SRV="$EVE_TPM_STATE/srv.sock"

echo "[+] Installing swtpm and tpm2-tools ..."
sudo apt-get -qq update -y > /dev/null
sudo apt-get install swtpm tpm2-tools -y -qq > /dev/null

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
    --flags not-need-init,startup-clear &

PID=$!

# set Transmission Interface (TCTI) swtpm socket, so tpm2-tools use it
# instead of the default char device interface.
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=$TPM_SRV_PORT"

# start fresh
tpm2 clear

# create Endorsement Key
tpm2 createek -c ek.ctx

# this setup seems very fragile, and quickly errors out with
# "out of memory for object contexts", so flush everything to be safe.
flushtpm

# create Storage Root Key
tpm2 startauthsession --policy-session -S session.ctx
tpm2 policysecret -S session.ctx -c $ENDO_SEED
tpm2 create -C ek.ctx -P "session:session.ctx" -G rsa2048 -u srk.pub -r srk.priv \
            -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth'
tpm2 flushcontext session.ctx
flushtpm

# load the srk
tpm2 startauthsession --policy-session -S session.ctx
tpm2 policysecret -S session.ctx -c $ENDO_SEED
tpm2 load -C ek.ctx -P "session:session.ctx" -u srk.pub -r srk.priv -c srk.ctx
tpm2 flushcontext session.ctx
flushtpm

# make persisted know-good-handles out of ek and srk
tpm2 evictcontrol -C o -c ek.ctx $EK_HANDLE
tpm2 evictcontrol -C o -c srk.ctx $SRK_HANDLE

# clean up
rm session.ctx ek.ctx srk.pub srk.priv srk.ctx

# just dump persistent handles, good for debugging§
tpm2 getcap handles-persistent

# kill swtpm
kill $PID

# start swtpm again, but this time with unix sockets for tests to use.
# in case we need to debug this, cat the log file.
swtpm socket --tpm2 \
    --flags startup-clear \
    --server type=unixio,path="$EVE_TPM_SRV" \
    --ctrl type=unixio,path="$EVE_TPM_CTRL" \
    --tpmstate dir="$EVE_TPM_STATE" \
    --log file="$EVE_TPM_STATE/swtpm.log"&

# copy test data, so it is accessible from the go tests
cp "tests/tpm/testdata/binary_bios_measurement" $EVE_TPM_STATE
cp "tests/tpm/testdata/measurefs_tpm_event_log" $EVE_TPM_STATE

# give swtpm time to start and init the TPM
sleep 1

# run tests
echo "[+] Running tests ..."
echo "========================================================"
for T in "${TESTS[@]}"; do
  name=$(basename "$T")
  cd pkg$T && go test -v -coverprofile="$name.coverage.txt" -covermode=atomic
done

#!/bin/sh
#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

DEV_KEY=0
EK_KEY=1
SRK_KEY=2
AK_KEY=3
QT_KEY=4
ECDH_KEY=5

EK_INDEX=0x81000001
SRK_INDEX=0x81000002
AK_INDEX=0x81000003
QT_INDEX=0x81000004
ECDH_INDEX=0x81000005
DEVKEY_INDEX=0x817FFFFF
VAULT_PRIV_INDEX=0x1800000
VAULT_PUB_INDEX=0x1900000
TEST_COUNT=100
PCR_HASH="sha256"
PCR_INDEX="0, 1, 2, 3, 4, 6, 7, 8, 9, 13, 14"
TPM_RECOV="/opt/debug/usr/bin/recovertpm"
VTPM_PATH="/opt/vtpm/"
TPM_TOOL="$VTPM_PATH""usr/bin/tpm2"
TPM_TOOL_LIB="$VTPM_PATH""usr/local/lib/"

# we don't install tpm2-abrmd, so tell tpm-tools to use tpmrm0.
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"

# create required file
echo "123456" > tpmcred
echo "secret" > secret

echo "======= Testing TPM info ======="
echo "1) Getting TPM info..."
if ! "$TPM_RECOV" -info; then
    echo "[ERROR] TPM info failed"
    exit 1
fi

echo "======= Testing key generation ======="
echo "1) Generating EK..."
if ! "$TPM_RECOV" -gen-key "$EK_KEY" -key-index "$EK_INDEX"; then
    echo "[ERROR] Key generation failed"
    exit 1
fi
echo "[?] Checking key..."
if ! LD_LIBRARY_PATH="$TPM_TOOL_LIB" "$TPM_TOOL" getcap handles-persistent | grep "$EK_INDEX"; then
    echo "[ERROR] EK not found when it should have been created"
    exit 1
else
    echo "[OK] EK found"
fi

echo "2) Generating SRK..."
if ! "$TPM_RECOV" -gen-key "$SRK_KEY" -key-index "$SRK_INDEX"; then
    echo "[ERROR] Key generation failed"
    exit 1
fi
echo "[?] Checking key..."
if ! LD_LIBRARY_PATH="$TPM_TOOL_LIB" "$TPM_TOOL" getcap handles-persistent | grep "$SRK_INDEX"; then
    echo "[ERROR] SRK not found when it should have been created"
    exit 1
else
    echo "[OK] SRK found"
fi

echo "3) Generating AK..."

if ! "$TPM_RECOV" -gen-key "$AK_KEY" -key-index "$AK_INDEX"; then
    echo "[ERROR] Key generation failed"
    exit 1
fi
echo "[?] Checking key..."
if ! LD_LIBRARY_PATH="$TPM_TOOL_LIB" "$TPM_TOOL" getcap handles-persistent | grep "$AK_INDEX"; then
    echo "[ERROR] AK not found when it should have been created"
    exit 1
else
    echo "[OK] AK found"
fi

echo "4) Generating Quote Key..."
if ! "$TPM_RECOV" -gen-key "$QT_KEY" -key-index "$QT_INDEX"; then
    echo "[ERROR] Key generation failed"
    exit 1
fi
echo "[?] Checking key..."
if ! LD_LIBRARY_PATH="$TPM_TOOL_LIB" "$TPM_TOOL" getcap handles-persistent | grep "$QT_INDEX"; then
    echo "[ERROR] QT not found when it should have been created"
    exit 1
else
    echo "[OK] QT found"
fi

echo "5) Generating ECC Key..."
if ! "$TPM_RECOV" -gen-key "$ECDH_KEY" -key-index "$ECDH_INDEX"; then
    echo "[ERROR] Key generation failed"
    exit 1
fi
echo "[?] Checking key..."
if ! LD_LIBRARY_PATH="$TPM_TOOL_LIB" "$TPM_TOOL" getcap handles-persistent | grep "$ECDH_INDEX"; then
    echo "[ERROR] ECDH not found when it should have been create"
    exit 1
else
    echo "[OK] ECDH found"
fi

echo "6) Generating Device Key..."
if ! "$TPM_RECOV" -gen-key "$DEV_KEY" -key-index "$DEVKEY_INDEX" -tpm-cred tpmcred; then
    echo "[ERROR] Key generation failed"
    exit 1
fi
echo "[?] Checking key..."
if ! LD_LIBRARY_PATH="$TPM_TOOL_LIB" "$TPM_TOOL" getcap handles-persistent | grep "$DEVKEY_INDEX"; then
    echo "[ERROR] Device Key not found when it should have been created"
    exit 1
else
    echo "[OK] Device Key found"
fi

echo "======= Testing key removal ======="
echo "1) Removing EK..."
if ! "$TPM_RECOV" -remove-key -key-index "$EK_INDEX"; then
    echo "[ERROR] Key removal failed"
    exit 1
fi
echo "[?] Checking key..."
if LD_LIBRARY_PATH="$TPM_TOOL_LIB" "$TPM_TOOL" getcap handles-persistent | grep "$EK_INDEX"; then
    echo "[ERROR] EK found when it should have been removed"
    exit 1
else
    echo "[OK] EK not found"
fi

echo "2) Removing SRK..."
if ! "$TPM_RECOV" -remove-key -key-index "$SRK_INDEX"; then
    echo "[ERROR] Key removal failed"
    exit 1
fi
echo "[?] Checking key..."
if LD_LIBRARY_PATH="$TPM_TOOL_LIB" "$TPM_TOOL" getcap handles-persistent | grep "$SRK_INDEX"; then
    echo "[ERROR] SRK found when it should have been removed"
    exit 1
else
    echo "[OK] SRK not found"
fi

echo "3) Removing AK..."
if ! "$TPM_RECOV" -remove-key -key-index "$AK_INDEX"; then
    echo "[ERROR] Key removal failed"
    exit 1
fi
echo "[?] Checking key..."
if LD_LIBRARY_PATH="$TPM_TOOL_LIB" "$TPM_TOOL" getcap handles-persistent | grep "$AK_INDEX"; then
    echo "[ERROR] AK found when it should have been removed"
    exit 1
else
    echo "[OK] AK not found"
fi

echo "4) Removing Quote Key..."
if ! "$TPM_RECOV" -remove-key -key-index "$QT_INDEX"; then
    echo "[ERROR] Key removal failed"
    exit 1
fi
echo "[?] Checking key..."
if LD_LIBRARY_PATH="$TPM_TOOL_LIB" "$TPM_TOOL" getcap handles-persistent | grep "$QT_INDEX"; then
    echo "[ERROR] QT found when it should have been removed"
    exit 1
else
    echo "[OK] QT not found"
fi

echo "5) Removing ECDH Key..."
if ! "$TPM_RECOV" -remove-key -key-index "$ECDH_INDEX"; then
    echo "[ERROR] Key removal failed"
    exit 1
fi
echo "[?] Checking key..."
if LD_LIBRARY_PATH="$TPM_TOOL_LIB" "$TPM_TOOL" getcap handles-persistent | grep "$ECDH_INDEX"; then
    echo "[ERROR] ECDH found when it should have been removed"
    exit 1
else
    echo "[OK] ECDH not found"
fi

echo "6) Removing Device Key..."
if ! "$TPM_RECOV" -remove-key -key-index "$DEVKEY_INDEX"; then
    echo "[ERROR] Key removal failed"
    exit 1
fi
echo "[?] Checking key..."
if LD_LIBRARY_PATH="$TPM_TOOL_LIB" "$TPM_TOOL" getcap handles-persistent | grep "$DEVKEY_INDEX"; then
    echo "[ERROR] Device Key found when it should have been removed"
    exit 1
else
    echo "[OK] Device Key not found"
fi

echo "======= Testing seal and export ======="
echo "1) Generating SRK Key..."
if ! "$TPM_RECOV" -gen-key $SRK_KEY -key-index "$SRK_INDEX"; then
    echo "[ERROR] Key generation failed"
    exit 1
fi

echo "2) Sealing key..."
if ! "$TPM_RECOV" -seal-key -input "$PWD/secret" -vpub-index "$VAULT_PUB_INDEX" -vpriv-index "$VAULT_PRIV_INDEX" -pcr-index "$PCR_INDEX" -pcr-hash "$PCR_HASH"; then
    echo "[ERROR] Sealing failed"
    exit 1
fi
echo "[?] Checking key..."
if ! LD_LIBRARY_PATH="$TPM_TOOL_LIB" "$TPM_TOOL" getcap handles-nv-index | grep "$VAULT_PUB_INDEX"; then
    echo "[ERROR] Vault public key not found when it should have been created"
    exit 1
else
    echo "[OK] Vault public key found"
fi
if ! LD_LIBRARY_PATH="$TPM_TOOL_LIB" "$TPM_TOOL" getcap handles-nv-index | grep "$VAULT_PRIV_INDEX"; then
    echo "[ERROR] Vault private key not found when it should have been created"
    exit 1
else
    echo "[OK] Vault private key found"
fi

echo "3) Generating Device Key..."
if ! "$TPM_RECOV" -gen-key "$DEV_KEY" -key-index "$DEVKEY_INDEX" -tpm-cred tpmcred; then
    echo "[ERROR] Key generation failed"
    exit 1
fi

echo "5) Generating ECC Key..."
if ! "$TPM_RECOV" -gen-key "$ECDH_KEY" -key-index "$ECDH_INDEX"; then
    echo "[ERROR] Key generation failed"
    exit 1
fi

echo "3) Exporting sealed key..."
if ! "$TPM_RECOV" -export-vkey -output secret.exp -vpub-index "$VAULT_PUB_INDEX" -vpriv-index "$VAULT_PRIV_INDEX" -pcr-index "$PCR_INDEX" -pcr-hash "$PCR_HASH" -ecdh-index "$ECDH_INDEX" -devkey-index "$DEVKEY_INDEX"; then
    echo "[ERROR] Export failed"
    exit 1
fi
echo "[OK] Key exported"

echo "======= Running TPM sainity tests ======="
echo "1) Test ECDH with default device key and ECC key (Test Count : $TEST_COUNT)..."
if ! "$TPM_RECOV" -test 0 -ecdh-index "$ECDH_INDEX" -devkey-index "$DEVKEY_INDEX" -test-count "$TEST_COUNT" -show-bar; then
    echo "[ERROR] Test failed"
    exit 1
fi

echo "2) Generated a new ECC key and test ECDH (Test Count : $TEST_COUNT)..."
if ! "$TPM_RECOV" -test 1 -ecdh-index "$ECDH_INDEX" -devkey-index "$DEVKEY_INDEX" -test-count "$TEST_COUNT" -show-bar -test-key-regen; then
    echo "[ERROR] Test failed"
    exit 1
fi

echo "3) Generate a device key and test ECDH (Test Count : $TEST_COUNT)..."
if ! "$TPM_RECOV" -test 2 -tpm-cred tpmcred -ecdh-index "$ECDH_INDEX" -devkey-index "$DEVKEY_INDEX" -test-count "$TEST_COUNT" -show-bar -test-key-regen; then
    echo "[ERROR] Test failed"
    exit 1
fi

echo "4) Generate a new ECC key and device key, and test ECDH (Test Count : $TEST_COUNT)..."
if ! "$TPM_RECOV" -test 3 -tpm-cred tpmcred -ecdh-index "$ECDH_INDEX" -devkey-index "$DEVKEY_INDEX" -test-count "$TEST_COUNT" -show-bar -test-key-regen; then
    echo "[ERROR] Test failed"
    exit 1
fi

echo "[OK] All TPM checks PASSED"
rm -f tpmcred secret secret.exp*

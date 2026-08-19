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
TPM_TOOL="/usr/bin/tpm2"
TPM_TOOL_LIB="/usr/lib/"
# Must match recovertpm's own default for -tpm-cred.
TPM_CRED="/config/tpm_credential"
# The installer treats the presence of this file as "the device certificate is not
# TPM-backed", so its absence is what makes the device key ours to restore.
SOFT_DEV_KEY="/config/device.key.pem"

# we don't install tpm2-abrmd, so tell tpm-tools to use tpmrm0.
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"

# $1 is the getcap listing to search (persistent or nv-index), $2 the handle.
# shellcheck disable=SC2317,SC2329  # false positives: only reached from the trap handler
tpm_has_handle() {
    LD_LIBRARY_PATH="$TPM_TOOL_LIB" "$TPM_TOOL" getcap "handles-$1" 2>/dev/null |
        grep -q "$2"
}

# Everything the checks do is destructive, and what they leave behind is not
# usable by the installed system: the device key ends up owned by the test
# credential rather than the one in /config, and the vault's NV pair holds the
# test payload. Nothing repairs that later -- pillar re-creates missing keys on
# every boot but never touches the device key handle -- so a node installed with
# a TPM present cannot sign the controller handshake and never onboards. Restore
# runs from an EXIT trap so that a check failing partway cannot skip it.
# shellcheck disable=SC2317,SC2329  # false positives: function is called via trap
restore_tpm_state() {
    checks_status=$?
    restore_failed=""

    echo "======= Restoring TPM state ======="

    echo "1) Removing the test seal..."
    for index in "$VAULT_PRIV_INDEX" "$VAULT_PUB_INDEX"; do
        tpm_has_handle nv-index "$index" || continue
        if LD_LIBRARY_PATH="$TPM_TOOL_LIB" "$TPM_TOOL" nvundefine "$index" -C o; then
            echo "[OK] $index removed"
        else
            echo "[ERROR] Failed to undefine $index"
            restore_failed=1
        fi
    done

    # recovertpm defaults -tpm-cred to /config/tpm_credential, so the device key
    # has to be generated without the flag the tests pass. Absent that credential
    # the installer did not provision a TPM-backed device certificate and EVE
    # creates the key on first boot, so leave the handle empty rather than
    # claiming it with a password nothing else knows.
    echo "2) Restoring the device key..."
    if [ -f "$TPM_CRED" ] && [ ! -f "$SOFT_DEV_KEY" ]; then
        if "$TPM_RECOV" -gen-key "$DEV_KEY" -key-index "$DEVKEY_INDEX" &&
                "$TPM_RECOV" -check-dev-cert; then
            echo "[OK] Device Key restored"
        else
            echo "[ERROR] Failed to restore the device key"
            restore_failed=1
        fi
    elif ! tpm_has_handle persistent "$DEVKEY_INDEX"; then
        echo "[OK] Device Key left for first boot"
    elif "$TPM_RECOV" -remove-key -key-index "$DEVKEY_INDEX"; then
        echo "[OK] Device Key left for first boot"
    else
        echo "[ERROR] Failed to remove the device key"
        restore_failed=1
    fi

    # EK, AK and quote are removed by the checks and never re-created. Pillar
    # brings back whatever is missing on every boot, so this only closes the
    # window between install and first boot.
    echo "3) Restoring the remaining keys..."
    for key in "$EK_KEY:$EK_INDEX" "$AK_KEY:$AK_INDEX" "$QT_KEY:$QT_INDEX"; do
        if "$TPM_RECOV" -gen-key "${key%:*}" -key-index "${key#*:}"; then
            echo "[OK] ${key#*:} restored"
        else
            echo "[ERROR] Key generation failed for ${key#*:}"
            restore_failed=1
        fi
    done

    rm -f tpmcred secret secret.exp*

    if [ -n "$restore_failed" ]; then
        echo "[ERROR] TPM state could not be restored"
    elif [ "$checks_status" -eq 0 ]; then
        echo "[OK] All TPM checks PASSED"
    fi
}

# create required file
echo "123456" > tpmcred
echo "secret" > secret

echo "======= Testing TPM info ======="
echo "1) Getting TPM info..."
if ! "$TPM_RECOV" -info; then
    echo "[ERROR] TPM info failed"
    exit 1
fi

# Armed only once the TPM is known to answer, and before anything is changed.
trap 'restore_tpm_state' EXIT

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

exit 0

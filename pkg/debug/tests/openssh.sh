#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# Run only in the disposable Docker test stage: this adds test accounts to /out.
set -eu

root=/out
mkdir -p "$root/ssh-test" "$root/dev"
[ -e "$root/dev/null" ] || mknod -m 666 "$root/dev/null" c 1 3
printf 'ssh-test:x:60000:60000:SSH test:/ssh-test:/bin/sh\nssh-salt:x:60001:60000:Salt donor:/ssh-test:/bin/sh\n' >> "$root/etc/passwd"
printf 'ssh-test:x:60000:\n' >> "$root/etc/group"
# The bypass requires a '*' account and another account with a real hash.
hash=$(openssl passwd -6 -salt eve-ssh-test test-only-password)
printf 'ssh-test:*:20000:0:99999:7:::\nssh-salt:%s:20000:0:99999:7:::\n' "$hash" >> "$root/etc/shadow"
chroot "$root" /usr/bin/ssh-keygen -q -t ed25519 -N '' -f /ssh-test/host_key
chroot "$root" /usr/bin/ssh-keygen -q -t ed25519 -N '' -f /ssh-test/client_key
cp "$root/ssh-test/client_key.pub" "$root/ssh-test/authorized_keys"
cat > "$root/ssh-test/sshd_config" <<'CONFIG'
ListenAddress 127.0.0.1
Port 22222
HostKey /ssh-test/host_key
PidFile /ssh-test/sshd.pid
AuthorizedKeysFile /ssh-test/authorized_keys
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM no
Subsystem sftp /usr/lib/ssh/sftp-server
CONFIG
cat > "$root/ssh-test/askpass" <<'ASKPASS'
#!/bin/sh
# The first failed attempt initializes OpenSSH's cached salt. Reuse the same
# connection so shadow_pw's static buffer no longer gets overwritten by that scan.
if [ ! -e /ssh-test/attempted ]; then
    touch /ssh-test/attempted
    echo wrong-password
    exit 0
fi
awk 'BEGIN { for (i=0; i<300; i++) printf "A"; print "" }'
ASKPASS
chmod 755 "$root/ssh-test/askpass"
chroot "$root" /usr/sbin/sshd -D -e -f /ssh-test/sshd_config > /tmp/openssh-test.log 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || :; wait "$server" 2>/dev/null || :' EXIT
ready=false
for _attempt in $(seq 1 50); do
    if chroot "$root" /usr/bin/ssh-keyscan -p 22222 127.0.0.1 >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 0.1
done
if [ "$ready" != true ]; then cat /tmp/openssh-test.log; exit 1; fi

# Password authentication is deliberately ON here: test the upstream fix,
# independently of EVE's production publickey-only mitigation.
if DISPLAY=:0 SSH_ASKPASS_REQUIRE=force SSH_ASKPASS=/ssh-test/askpass \
    chroot "$root" /usr/bin/ssh -F /dev/null -p 22222 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=2 ssh-test@127.0.0.1 true; then
    echo 'ERROR: password bypass succeeded' >&2
    exit 1
fi
grep -q 'Failed password for ssh-test' /tmp/openssh-test.log
result=$(chroot "$root" /usr/bin/ssh -F /dev/null -p 22222 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -i /ssh-test/client_key ssh-test@127.0.0.1 'printf publickey-ok')
[ "$result" = publickey-ok ]
printf 'pwd\n' > "$root/ssh-test/sftp.batch"
chroot "$root" /usr/bin/sftp -F /dev/null -P 22222 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -i /ssh-test/client_key -b /ssh-test/sftp.batch ssh-test@127.0.0.1
printf 'OpenSSH password-bypass rejection, publickey login and SFTP passed\n'

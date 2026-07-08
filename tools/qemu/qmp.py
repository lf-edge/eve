#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# Minimal QMP client: connect, negotiate, run an HMP command, print reply.
# Terse standalone diagnostic script: relax pylint style checks that
# don't add value here.
# pylint: disable=invalid-name,consider-using-f-string,missing-module-docstring,missing-class-docstring,missing-function-docstring,consider-using-with,unspecified-encoding,broad-exception-caught,multiple-imports,multiple-statements,too-many-locals,too-many-statements,unnecessary-lambda-assignment
import socket, json, sys, glob

def find_sock():
    # Use the control "qmp" socket (free); "listener.qmp" is held by the monitor service.
    g = glob.glob("/hostfs/run/hypervisor/kvm/*/qmp")
    return g[0] if g else None

def qmp(sock_path, hmp_cmd, timeout=10):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(sock_path)
    f = s.makefile("rwb", buffering=0)
    def recv():
        line = f.readline()
        return json.loads(line) if line else None
    recv()  # greeting
    f.write(b'{"execute":"qmp_capabilities"}\n')
    recv()  # capabilities ack
    cmd = {"execute": "human-monitor-command",
           "arguments": {"command-line": hmp_cmd}}
    f.write((json.dumps(cmd) + "\n").encode())
    # read until we get a return/error object
    while True:
        r = recv()
        if r is None:
            break
        if "return" in r or "error" in r:
            print(r.get("return", r.get("error")))
            break
    s.close()

if __name__ == "__main__":
    sock = find_sock()
    if not sock:
        sys.exit("no listener.qmp socket found")
    hmp = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "info version"
    qmp(sock, hmp)

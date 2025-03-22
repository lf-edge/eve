# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

import http.client
import socket
import messages_pb2

CID = socket.VMADDR_CID_HOST
PORT = 2000
EK_HANDLE = 0x81000001

class VsockHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, **kwargs):
        super().__init__("localhost", *args, **kwargs)

    def connect(self):
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.connect((CID, PORT))

tpm_req = messages_pb2.TpmRequestGetPub()
tpm_req.index = EK_HANDLE
protobuf_data = tpm_req.SerializeToString()
print(f"Serialized data: {protobuf_data}")

# Use the custom connection
conn = VsockHTTPConnection()
headers = {
    "Content-Type": "application/x-protobuf",
    "Content-Length": str(len(protobuf_data)),
}
conn.request("POST", "http://vsock/tpm/getpub", body=protobuf_data, headers=headers)
r = conn.getresponse()
print(r.status, r.reason)
while chunk := r.read(200):
    print(repr(chunk))
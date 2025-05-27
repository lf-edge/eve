# Copyright (c) 2020,2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

""" This script generates an EC key pair where the public key's x or y coordinate starts with a leading zero byte.
    This is useful for testing TPM behavior with such keys.
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def generate_key_with_leading_zero():
    """Generate an EC key pair with a public key coordinate that has a leading zero byte."""
    while True:
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_numbers = key.public_key().public_numbers()
        x_bytes = public_numbers.x.to_bytes(32, 'big')
        y_bytes = public_numbers.y.to_bytes(32, 'big')
        if x_bytes[0] == 0x00 and x_bytes[1] == 0x00:
            return key, x_bytes, y_bytes
        if y_bytes[0] == 0x00 and y_bytes[1] == 0x00:
            return key, x_bytes, y_bytes

private_key, x, y = generate_key_with_leading_zero()
print(f"Found coordinate with leading zero.\n X : {x.hex()}\n Y : {y.hex()}")

with open("ec_key_leading_zero.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

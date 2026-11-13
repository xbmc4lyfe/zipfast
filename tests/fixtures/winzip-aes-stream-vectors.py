# Copyright (C) 2026 xbmc4lyfe
# SPDX-License-Identifier: RPL-1.5
#
# Unless explicitly acquired and licensed from Licensor under another license,
# the contents of this file are subject to the Reciprocal Public License
# ("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
# may not copy or use this file in either source code or executable form,
# except in compliance with the terms and conditions of the RPL.
#
# All software distributed under the RPL is provided strictly on an "AS IS"
# basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
# HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
# ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
# rights and limitations under the RPL.

"""Independent WinZip AES vectors using Python hashlib/HMAC and OpenSSL AES-ECB."""
import hashlib
import hmac
import subprocess

password = ("a native AES fixture password with UTF-8 雪 " + "p" * 67).encode()
print("# strength length verifier ciphertext_sha1 authentication_tag")
for strength, key_bytes, salt_bytes in [(1, 16, 8), (2, 24, 12), (3, 32, 16)]:
    salt = bytes(range(1, salt_bytes + 1))
    derived = hashlib.pbkdf2_hmac("sha1", password, salt, 1000, 2 * key_bytes + 2)
    for length in [0, 1, 15, 16, 17, 63, 64, 65, 65535, 65536, 65537]:
        payload = bytes((i * 73 + (i >> 8) + 19) % 256 for i in range(length))
        counters = b"".join(i.to_bytes(16, "little") for i in range(1, (length + 15) // 16 + 1))
        blocks = subprocess.run(
            ["openssl", "enc", f"-aes-{key_bytes * 8}-ecb", "-K", derived[:key_bytes].hex(), "-nopad"],
            input=counters, capture_output=True, check=True,
        ).stdout
        ciphertext = bytes(a ^ b for a, b in zip(payload, blocks))
        tag = hmac.digest(derived[key_bytes:2 * key_bytes], ciphertext, "sha1")[:10]
        print(strength, length, derived[-2:].hex(), hashlib.sha1(ciphertext).hexdigest(), tag.hex())

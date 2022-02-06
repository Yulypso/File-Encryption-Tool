#!/usr/bin/env python3

'''
Author: Thierry Khamphousone @Yulypso
Date: 03/02/2022
'''

import sys
from typing import Optional
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import binascii


def derivate_password(password: bytes, salt: bytes, counter: int) -> Optional[bytes]:
    h = SHA256.new(data=None)
    h.update(password)
    h.update(salt)
    h.update((0).to_bytes(4, byteorder='little'))
    h0 = h.digest()

    hi = h0

    for i in range(1, counter):
        h = SHA256.new(data=None)
        h.update(hi)
        h.update(password)
        h.update(salt)
        h.update(i.to_bytes(4, byteorder='little'))
        hi = h.digest()

    return hi


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('required 1 argument')
        sys.exit(1)

    print(binascii.hexlify(derivate_password(
        sys.argv[1].encode(), sys.argv[2].encode(), int(sys.argv[3]))).decode('utf-8'))
    sys.exit(0)

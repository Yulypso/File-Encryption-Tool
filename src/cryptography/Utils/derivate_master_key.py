#!/usr/bin/env python3

'''
Author: Thierry Khamphousone @Yulypso
Date: 03/02/2022
'''

from Crypto.Hash import SHA256

def derivate_master_key(km: bytes) -> tuple:
    h = SHA256.new(data=None)
    h.update(km[0:32])
    h.update((0).to_bytes(4, byteorder='little'))
    kc = h.digest()

    h.update(km[0:32])
    h.update((1).to_bytes(4, byteorder='little'))
    ki = h.digest()

    return (kc, ki)
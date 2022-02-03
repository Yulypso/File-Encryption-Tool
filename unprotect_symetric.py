#!/usr/bin/env python3

'''
Author: Thierry Khamphousone
Date: 03/02/2022
'''

import sys
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import HMAC, SHA256
from Utils.derivate_password import derivate_password


def derivate_master_key(km: bytes) -> tuple:
    h = SHA256.new(data=None)
    h.update(km[0:32])
    h.update((0).to_bytes(4, byteorder='little'))
    kc = h.digest()

    h.update(km[0:32])
    h.update((1).to_bytes(4, byteorder='little'))
    ki = h.digest()

    return (kc, ki)


def unprotect_symetric(password: bytes, in_file: str) -> bytes:
    try:
        with open(in_file, 'rb') as fin:
            mac = fin.read(32)
            iv = fin.read(16)
            salt = fin.read(8)
            c = fin.read()

        # 01 - Derivate password
        km = derivate_password(password=password, salt=salt, counter=8192)

        # 02 - Derivate master key
        kc, ki = derivate_master_key(km=km)

        # 03 - Verify MAC
        try:
            h = HMAC.new(ki, digestmod=SHA256)
            h.update(iv)
            h.update(salt)
            h.update(c)

            h.verify(mac)

            # 04 - Déchiffrer les données
            aes = AES.new(kc, AES.MODE_CBC, iv)
            pt = unpad(aes.decrypt(c), AES.block_size)

            return pt
        except ValueError:
            print("The message or the key is wrong")
    except (ValueError, KeyError):
        print("Incorrect decryption")


def generate_decrypt(out_file: str, plain_text: bytes) -> None:
    with open(out_file, 'wb') as fout:
        fout.write(plain_text)
    print(f'[+]: Decryption success: {out_file}')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f"Usage : {sys.argv[0]} <password> <input_file> <output_file>")
        sys.exit(1)

    generate_decrypt(sys.argv[3], unprotect_symetric(
        sys.argv[1].encode(), sys.argv[2]))
    sys.exit(0)

#!/usr/bin/env python3

'''
Author: Thierry Khamphousone
Date: 03/02/2022
'''

import sys
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import HMAC, SHA256
from Utils.derivate_password import derivate_password
from Utils.generate_key import generate_key


def derivate_master_key(km: bytes) -> tuple:
    h = SHA256.new(data=None)
    h.update(km[0:32])
    h.update((0).to_bytes(4, byteorder='little'))
    kc = h.digest()

    h.update(km[0:32])
    h.update((1).to_bytes(4, byteorder='little'))
    ki = h.digest()

    return (kc, ki)


def protect_symetric(password: bytes, in_file: str) -> None:
    # 01 - Derivate password
    salt = generate_key(8)
    km = derivate_password(password=password, salt=salt, counter=8192)

    # 02 - Derivate master key
    kc, ki = derivate_master_key(km=km)

    # 03 - Lecture fichier
    with open(in_file, 'rb') as fin:
        data = fin.read()

        # 04 - Chiffrer les données - Protection en confidentialité
        aes = AES.new(kc, AES.MODE_CBC, iv=generate_key(16))
        c = aes.encrypt(pad(data, AES.block_size))

        # 05 - Calculer le MAC - Protection en intégrité
        h = HMAC.new(ki, digestmod=SHA256)
        h.update(aes.iv)
        h.update(salt)
        h.update(c)
        mac = h.digest()

    return (mac, aes.iv, salt, c)


def generate_encrypt(out_file: str, parameters: tuple) -> None:
    mac, iv, salt, c = parameters
    with open(out_file, 'wb') as fout:
        fout.write(mac + iv + salt + c)
    print(f'[+]: Encryption success: {out_file}')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f"Usage : {sys.argv[0]} <password> <input_file> <output_file>")
        sys.exit(1)

    generate_encrypt(sys.argv[3], protect_symetric(
        sys.argv[1].encode(), sys.argv[2]))
    sys.exit(0)

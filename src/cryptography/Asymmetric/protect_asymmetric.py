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
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto import Random
from Crypto.Random import get_random_bytes


def derivate_key(km: bytes) -> bytes:
    h = SHA256.new(data=None)
    h.update(km[0:32])
    h.update((0).to_bytes(4, byteorder='little'))
    kc = h.digest()

    return kc


def protect_asymmetric(receiver_public_key: str, sender_private_key: str, in_file: str) -> tuple:
    # 01 - Generation de la clé de chiffrement et de l'IV
    kc = get_random_bytes(AES.key_size[2])
    iv = generate_key(16)

    # 02 - Chiffrement des données (kc) -> c
    with open(in_file, 'rb') as fin:
        data = fin.read()
        aes = AES.new(kc, AES.MODE_CBC, iv=iv)
        c = aes.encrypt(pad(data, AES.block_size))

    # 03 - Chiffrement de la clé (pub_key) -> w
    pub_key = RSA.importKey(open(receiver_public_key).read())
    cipher = PKCS1_OAEP.new(pub_key)
    w = cipher.encrypt(kc)

    # 04 - Signature W C IV
    priv_key = RSA.import_key(open(sender_private_key).read())
    h = SHA256.new(w + c + iv)
    signature = pss.new(priv_key).sign(h)

    print(len(w))
    print(len(c))
    print(len(iv))
    print(len(signature))

    return (w, c, iv, signature)


def generate_encrypt(out_file: str, parameters: tuple) -> None:
    w, c, iv, signature = parameters
    with open(out_file, 'wb') as fout:
        fout.write(w + c + iv + signature)
    print(f'[+]: Encryption success: {out_file}')


if __name__ == '__main__':
    if len(sys.argv) != 5:
        print(
            f"Usage : {sys.argv[0]} <public_key_receiver> <private_key_sender> <input_file> <output_file>")
        sys.exit(1)

    generate_encrypt(sys.argv[4], protect_asymmetric(
        sys.argv[1], sys.argv[2], sys.argv[3]))
    sys.exit(0)

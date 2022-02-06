#!/usr/bin/env python3

'''
Author: Thierry Khamphousone @Yulypso
Date: 03/02/2022
'''


import sys, os, argparse
from typing import Hashable
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)

from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto import Random
from Crypto.Random import get_random_bytes

from Utils.derivate_password import derivate_password
from Utils.generate_key import generate_key
from Utils.derivate_master_key import derivate_master_key


def derivate_key(km: bytes) -> bytes:
    h = SHA256.new(data=None)
    h.update(km[0:32])
    h.update((0).to_bytes(4, byteorder='little'))
    kc = h.digest()

    return kc


def encrypt(in_file: str, private_key: str, public_key: str) -> tuple:
    '''
    Encryption using AES-256-CBC
    Input: bytes, receiver public_key, sender private_key
    Output: CIPHERKEY || CIPHERTEXT || IV || Signature(W|C|IV)
    '''
    # Secret kc and IV random generation
    kc = get_random_bytes(AES.key_size[2]) # AES KEY SIZE = 32 bytes
    iv = generate_key(AES.block_size)      # AES BLOCK SIZE = 16 bytes

    # Open and read plain file
    with open(in_file, 'rb') as fin:
        data = fin.read()

    # Data Encryption - Confidentiality    
    aes = AES.new(kc, AES.MODE_CBC, iv=iv)
    c_buffer = aes.encrypt(pad(data, AES.block_size))

    # Encryption of the Symmetric Key - Confidentiality    
    pub_key = RSA.importKey(open(public_key).read())
    cipher = PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)
    ckey_buffer = cipher.encrypt(kc)       # W = ckey_buffer

    # Signature W|iv|ciphered - Integrity
    priv_key = RSA.import_key(open(private_key).read())
    h = SHA256.new(ckey_buffer + c_buffer + iv)
    signature = pss.new(priv_key).sign(h)

    return (ckey_buffer, c_buffer, iv, signature)


def generate_encrypt_file(out_file: str, parameters: tuple) -> None:
    '''
    Write encrypted file bytes
    '''
    ckey_buffer, c_buffer, iv, signature = parameters
    with open(out_file, 'wb') as fout:
        fout.write(ckey_buffer + c_buffer + iv + signature)
    print(f'[+]: Encryption success: {out_file}')


def generate_decrypt_file(out_file: str, plain_text: bytes) -> None:
    '''
    Write decrypted file bytes
    '''
    with open(out_file, 'wb') as fout:
        fout.write(plain_text)
    print(f'[+]: Decryption success: {out_file}')


def arg_parser() -> None:
    '''
    Argument parser
    '''
    parser = argparse.ArgumentParser(
        add_help=True, description='AES-256-CBC symmetric encryption, RSA asymmetric encryption & RSA-SHA256 PKCS#1 PSS signature integrity check tool')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', help='Encryption mode', action='store_true')
    group.add_argument('-d', '--decrypt', help='Decryption mode', action='store_true')
    parser.add_argument('-priv', '--private', help='private key', dest='private_key', required=True)
    parser.add_argument('-pub', '--public', help='public key', dest='public_key', required=True)
    parser.add_argument('-i', '--in', help='input file', dest='fin', required=True)
    parser.add_argument('-o', '--out', help='output file', dest='fout', required=True)
    return parser


if __name__ == '__main__':

    args = arg_parser().parse_args()

    if args.encrypt:
        generate_encrypt_file(args.fout, encrypt(args.fin, args.private_key, args.public_key))
    #elif args.decrypt:
    #    generate_decrypt_file(args.fout, decrypt(args.fin, args.password.encode()))
    sys.exit(0)
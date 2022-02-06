#!/usr/bin/env python3

'''
Author: Thierry Khamphousone @Yulypso
Date: 03/02/2022
'''

import sys, os, argparse
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)

from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Utils.derivate_password import derivate_password
from Utils.generate_key import generate_key
from Utils.derivate_master_key import derivate_master_key


def encrypt(in_file: str, password: bytes) -> tuple:
    '''
    Encryption using AES-256-CBC
    Input: bytes
    Output: HMAC || IV || SALT || CIPHERTEXT
    '''
    # Derivate password
    salt = generate_key(length=8)
    iv = generate_key(length=16)
    km = derivate_password(password=password, salt=salt, counter=8192)

    # Derivate master key
    kc, ki = derivate_master_key(km=km)

    # Open and read plain file
    with open(in_file, 'rb') as fin:
        data = fin.read()

    # Encryption - Confidentiality
    aes = AES.new(kc, AES.MODE_CBC, iv=iv)
    c_buffer = aes.encrypt(pad(data, AES.block_size))

    # Signature - Integrity
    h = HMAC.new(key=ki, digestmod=SHA256)
    h.update(aes.iv)
    h.update(salt)
    h.update(c_buffer)
    hmac = h.digest()

    return (hmac, aes.iv, salt, c_buffer)


def decrypt(in_file: str, password: bytes) -> bytes:
    '''
    Decryption using AES-256-CBC
    Input: HMAC || IV || SALT || CIPHERTEXT
    Output: bytes
    '''
    with open(in_file, 'rb') as fin:
        hmac = fin.read(32)
        iv = fin.read(16)
        salt = fin.read(8)
        c_buffer = fin.read()

    # Derivate password
    km = derivate_password(password=password, salt=salt, counter=8192)

    # Derivate master key
    kc, ki = derivate_master_key(km=km)

    # Integrity check signature
    h = HMAC.new(key=ki, digestmod=SHA256)
    h.update(iv)
    h.update(salt)
    h.update(c_buffer)

    try:
        h.verify(hmac)

        # Decryption
        aes = AES.new(kc, AES.MODE_CBC, iv=iv)
        p_buffer = unpad(aes.decrypt(c_buffer), AES.block_size)
        return p_buffer
    except ValueError:
        print("The message or the key is wrong")
    return None

def generate_encrypt_file(out_file: str, parameters: tuple) -> None:
    '''
    Write encrypted file bytes
    '''
    mac, iv, salt, c = parameters
    with open(out_file, 'wb') as fout:
        fout.write(mac + iv + salt + c)
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
        add_help=True, description='AES-256-CBC encryption & HMAC-SHA256 integrity check tool')
    parser.add_argument('password', help='Secret password')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', help='Encryption mode', action='store_true')
    group.add_argument('-d', '--decrypt', help='Decryption mode', action='store_true')
    parser.add_argument('-i', '--in', help='input file', dest='fin', required=True)
    parser.add_argument('-o', '--out', help='output file', dest='fout', required=True)
    return parser


if __name__ == '__main__':

    args = arg_parser().parse_args()

    if args.encrypt:
        generate_encrypt_file(args.fout, encrypt(args.fin, args.password.encode()))
    elif args.decrypt:
        generate_decrypt_file(args.fout, decrypt(args.fin, args.password.encode()))
    sys.exit(0)

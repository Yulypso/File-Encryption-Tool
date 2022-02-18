#!/usr/bin/env python3

'''
Author: Thierry Khamphousone @Yulypso
Date: 03/02/2022
'''


from hashlib import sha256
from pydoc import plain
from re import S
from shutil import ExecError
import sys, os, argparse
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)

from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

from Utils.generate_key import generate_key


def generate_kc() -> bytes: 
    return generate_key(AES.key_size[2]) # AES KEY SIZE = 32 bytes


def generate_iv() -> bytes:
    return generate_key(AES.block_size)  # AES BLOCK SIZE = 16 bytes


def get_bytes_from_file(file: str):
    try:
        with open(file, 'rb') as f:
            return f.read()
    except:
        print(f'[!] File not found: {file}')
        sys.exit(1)


def symmetric_encryption(plain_b: bytes, kc: bytes, iv: bytes):
    aes = AES.new(kc, AES.MODE_CBC, iv=iv)
    return aes.encrypt(pad(plain_b, AES.block_size))


def append_dest(msg: bytes, SHA: bytes, RSA: bytes) -> bytes:
    return msg + b'\x00' + SHA + RSA


def end_dest(msg: bytes, C: bytes) -> bytes:
    return msg + b'\x01' + C


def encrypt(input_file: str, my_sign_priv_key: str, my_ciph_pub_key: str, users_ciph_pub: list) -> bytes:
    '''
    Encryption using AES-256-CBC
    Input: 
        - bytes to encrypt
        - my_ciph_pub_key, users_ciph_pub to encrypt the symmetric key 
        - my_sign_priv_key for signature
    Output: 0x00 || SHA256(kpub-1) || RSA_kpub-1(Kc || IV) || ... || 0x00 || SHA256(kpub-N) || RSA_kpub-N(Kc || IV) || 0x01 || C || Sign
    '''
    # Secret kc and IV random generation
    kc = generate_kc()
    iv = generate_iv()

    priv_key = RSA.import_key(get_bytes_from_file(my_sign_priv_key))

    # Data Encryption - Confidentiality    
    cipher_b = symmetric_encryption(get_bytes_from_file(input_file), kc, iv)

    # Encryption of the Symmetric Key for each pub key - Confidentiality    
    users_ciph_pub.insert(0, my_ciph_pub_key)

    msg = b''
    for user_ciph_pub in users_ciph_pub:
        pub_key = RSA.importKey(get_bytes_from_file(user_ciph_pub))
        cipher = PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)
        RSA_kpub = cipher.encrypt(kc + iv)    

        # Signature RSA_kpub - Integrity
        h = SHA256.new(get_bytes_from_file(user_ciph_pub))
        msg = append_dest(msg, h.digest(), RSA_kpub)

    msg = end_dest(msg, cipher_b)

    # Signature global msg - Integrity
    h = SHA256.new(msg)
    sign = pss.new(priv_key).sign(h)
    msg += sign

    return (msg)


def verify_signature(signed: bytes, signature: bytes, sender_sign_pub: bytes):
    pub_key = RSA.import_key(get_bytes_from_file(sender_sign_pub))
    h = SHA256.new(signed)
    verifier = pss.new(pub_key)

    try:
        verifier.verify(h, signature)
        print('[+]: The signature is authentic.')
    except:
        print('[!]: The signature is not authentic.')
        sys.exit(1)


def get_current_param(input_bytes):
    sha256 = input_bytes[1:33]
    RSA_kpub = input_bytes[33:33+256]
    return sha256, RSA_kpub, input_bytes[33+256:]

def get_kpub_sha256(input_bytes: bytes, my_ciph_pub_key: bytes):

    h = SHA256.new(my_ciph_pub_key)

    while(input_bytes[0].to_bytes(1, byteorder='little') != b'\x01'):
        sha256, RSA_kpub, input_bytes = get_current_param(input_bytes)
        found_sha256, found_RSA_kpub = b'', b''
        if sha256 == h.digest():
            found_sha256 = sha256
            found_RSA_kpub = RSA_kpub
    
    return found_sha256, found_RSA_kpub, input_bytes[1:]


def decrypt(input_file: str, my_ciph_priv_key: str, my_ciph_pub_key: str, sender_sign_pub: str) -> bytes:
    '''
    Encryption using AES-256-CBC
    Input: 0x00 || SHA256(kpub-1) || RSA_kpub-1(Kc || IV) || ... || 0x00 || SHA256(kpub-N) || RSA_kpub-N(Kc || IV) || 0x01 || C || Sign
    Output: bytes
    '''
    # Open input_file
    input_bytes = get_bytes_from_file(input_file)

    # Integrity check msg signature
    verify_signature(input_bytes[:-256], input_bytes[-256:], sender_sign_pub)

    sha256, RSA_kpub, cipher_b = get_kpub_sha256(input_bytes[:-256], get_bytes_from_file(my_ciph_pub_key))

    if len(sha256) < 1 or len(RSA_kpub) < 1 or len(cipher_b) < 1:
        print('[!]: Public key not found')
        sys.exit(1)

    print('[+]: Public key found')
    # Decryption of the symmetric key
    priv_key = RSA.importKey(get_bytes_from_file(my_ciph_priv_key))
    pkcs1 = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)
    dec = pkcs1.decrypt(RSA_kpub)
    kc = dec[:32]
    iv = dec[32:]

    # Data Decryption from kc decrypted
    aes = AES.new(kc, AES.MODE_CBC, iv)
    p_buffer = unpad(aes.decrypt(cipher_b), AES.block_size)

    return p_buffer 


def generate_encrypt_file(out_file: str, msg: bytes) -> None:
    '''
    Write encrypted file bytes
    '''
    try: 
        with open(out_file, 'wb') as fout:
            fout.write(msg)
        print(f'[+]: Encryption success: {out_file}')
    except:
        print(f'[+]: Encyption error: {out_file}')
        sys.exit(1)


def generate_decrypt_file(out_file: str, plain_text: bytes) -> None:
    '''
    Write decrypted file bytes
    '''
    try:
        with open(out_file, 'wb') as fout:
            fout.write(plain_text)
            print(f'[+]: Decryption success: {out_file}')
    except:
        print(f'[!]: Decryption error: {out_file}')
        sys.exit(1)

def encryption_mode(args):
    generate_encrypt_file(args.output_file, encrypt(args.input_file, args.my_sign_priv_key, args.my_ciph_pub_key, args.users_ciph_pub))
    sys.exit(0)

def decryption_mode(args):
    generate_decrypt_file(args.output_file, decrypt(args.input_file, args.my_ciph_priv_key, args.my_ciph_pub_key, args.sender_sign_pub))
    sys.exit(0)

def arg_parser() -> None:
    '''
    Argument parser
    '''
    parser = argparse.ArgumentParser(
        add_help=True, description='Multi user encryption tool: AES-256-CBC symmetric encryption, RSA asymmetric encryption & RSA-SHA256 PKCS#1 PSS signature integrity check')

    subparsers = parser.add_subparsers(help='Multi User Encryption Mode')

    group_encrypt = subparsers.add_parser(name='e', help='Encryption Mode')
    group_encrypt.add_argument('input_file', help='plain input file')
    group_encrypt.add_argument('output_file', help='encrypted output file')
    group_encrypt.add_argument('my_sign_priv_key', help='my private signature key')
    group_encrypt.add_argument('my_ciph_pub_key', help='my public cipher key')
    group_encrypt.add_argument('users_ciph_pub', help='users public cipher key', nargs='+')
    group_encrypt.set_defaults(func=encryption_mode)

    group_decrypt = subparsers.add_parser(name='d', help='Decryption Mode')
    group_decrypt.add_argument('input_file', help='encrypted input file')
    group_decrypt.add_argument('output_file', help='decrypted output file')
    group_decrypt.add_argument('my_ciph_priv_key', help='my private cipher key')
    group_decrypt.add_argument('my_ciph_pub_key', help='my public cipher key')
    group_decrypt.add_argument('sender_sign_pub', help='sender public signature key')
    group_decrypt.set_defaults(func=decryption_mode)

    return parser


if __name__ == '__main__':

    if len(sys.argv) <= 1:
        args = arg_parser().parse_args(['-h'])
    else:
        args = arg_parser().parse_args()
        args.func(args)
    sys.exit(0)
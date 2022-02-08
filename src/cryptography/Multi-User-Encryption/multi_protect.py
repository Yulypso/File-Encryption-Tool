#!/usr/bin/env python3

'''
Author: Thierry Khamphousone @Yulypso
Date: 03/02/2022
'''


from re import S
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
    Output: CIPHERKEY || IV || Signature(W|C|IV) || CIPHERTEXT
    '''
    # Secret kc and IV random generation
    kc = generate_key(AES.key_size[2]) # AES KEY SIZE = 32 bytes
    iv = generate_key(AES.block_size)  # AES BLOCK SIZE = 16 bytes

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

    return (ckey_buffer, iv, signature, c_buffer)


def decrypt(in_file: str, private_key: str, public_key: str) -> tuple:
    '''
    Encryption using AES-256-CBC
    Input: CIPHERKEY || IV || Signature(W|C|IV), receiver private_key, sender public_key || CIPHERTEXT
    Output: bytes
    '''
    # Open and read parameters & plain file
    with open(in_file, 'rb') as fin:
        ckey_buffer = fin.read(int(RSA.importKey(open(private_key).read()).size_in_bytes()))
        iv = fin.read(AES.block_size) # AES BLOCK SIZE = 16 bytes
        signature = fin.read(int(RSA.importKey(open(public_key).read()).size_in_bytes()))
        c_buffer = fin.read()

    #  Integrity check signature
    pub_key = RSA.import_key(open(public_key).read())
    h = SHA256.new(ckey_buffer + c_buffer + iv)
    verifier = pss.new(pub_key)

    try:
        verifier.verify(h, signature)
        print('The signature is authentic.')
    except:
        print('The signature is not authentic.')
        sys.exit(1)

    # Decryption of the symmetric key
    priv_key = RSA.importKey(open(private_key).read())
    pkcs1 = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)
    kc = pkcs1.decrypt(ckey_buffer)

    # Data Decryption from kc decrypted
    aes = AES.new(kc, AES.MODE_CBC, iv)
    p_buffer = unpad(aes.decrypt(c_buffer), AES.block_size)

    return p_buffer


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
        add_help=True, description='Multi user encryption tool: AES-256-CBC symmetric encryption, RSA asymmetric encryption & RSA-SHA256 PKCS#1 PSS signature integrity check')

    subparsers = parser.add_subparsers(help="Multi User Encryption Mode")

    group_encrypt = subparsers.add_parser("encryption", help="Encryption Mode")
    group_encrypt.add_argument('-e', '--encrypt', help='Encryption mode', action='store_true', default=False, dest='encrypt', required=True)
    group_encrypt.add_argument('input_file', help='plain input file')
    group_encrypt.add_argument('output_file', help='encrypted output file')
    group_encrypt.add_argument('my_sign_priv_key', help='my private signature key')
    group_encrypt.add_argument('my_ciph_pub_key', help='my public cipher key')
    group_encrypt.add_argument('users_ciph_pub', help='users public cipher key', nargs='+')

    group_decrypt = subparsers.add_parser("decryption", help="Decryption Mode")
    group_decrypt.add_argument('-d', '--decrypt', help='Decryption mode', action='store_true', default=False, dest='decrypt', required=True)
    group_decrypt.add_argument('input_file', help='encrypted input file')
    group_decrypt.add_argument('output_file', help='decrypted output file')
    group_decrypt.add_argument('my_ciph_priv_key', help='my private cipher key')
    group_decrypt.add_argument('my_ciph_pub_key', help='my public cipher key')
    group_decrypt.add_argument('sender_sign_pub', help='sender public signature key', nargs='+')
    
    return parser

# $ python multi_protect.py -e <input_file> <output_file> <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]

# python multi_protect.py -d <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem>


if __name__ == '__main__':

    args = arg_parser().parse_args()
    if 'encrypt' in args:
        # python3 multi_protect.py encryption -e ../../../plain ../../../encrypt ../../../key-pair-1/signature-1-priv.pem ../../../key-pair-1/cipher-1-pub.pem ../../../key-pair-2/cipher-2-pub.pem ../../../key-pair-3/cipher-3-pub.pem
        print("encrytion")
        #generate_encrypt_file(args.fout, encrypt(args.fin, args.private_key, args.public_key))
    elif 'decrypt' in args:
        # python3 multi_protect.py decryption -d ../../../encrypt ../../../decrypt ../../../key-pair-2/cipher-2-priv.pem ../../../key-pair-2/cipher-2-pub.pem ../../../key-pair-1/signature-1-pub.pem
        print("decryption")
        #generate_decrypt_file(args.fout, decrypt(args.fin, args.private_key, args.public_key))
    
    sys.exit(0)
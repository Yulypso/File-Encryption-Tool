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
    with open(file, 'rb') as f:
        return f.read()

def symmetric_encryption(plain_b: bytes, kc: bytes, iv: bytes):
    aes = AES.new(kc, AES.MODE_CBC, iv=iv)
    return aes.encrypt(pad(plain_b + kc + iv, AES.block_size))

def append_dest(msg: bytes, RSA: bytes, SHA: bytes) -> bytes:
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
        msg = append_dest(msg, RSA_kpub, h.digest())

    msg = end_dest(msg, cipher_b)

    print(cipher_b)

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
        print('The signature is authentic.')
    except:
        print('The signature is not authentic.')
        sys.exit(1)


def get_kpub_sha256(input_bytes: bytes, my_ciph_pub_key: bytes):
    sha256 = b''
    kpub = b''

    read_sha256 = False
    read_kpub = False
    read_cipher = False
    found = False

    out_sha256 = b''
    out_kpub = b''
    cipher_b = b''

    h = SHA256.new(my_ciph_pub_key)

    for b in input_bytes:
        if read_cipher == True:
            cipher_b += b.to_bytes(1, byteorder='little')
        else:
            if read_sha256 == True:
                sha256 += b.to_bytes(1, byteorder='little')

            elif read_kpub == True:
                kpub += b.to_bytes(1, byteorder='little')

            if (b.to_bytes(1, byteorder='little') == b'\x00' or b.to_bytes(1, byteorder='little') == b'\x01') and read_sha256 == False:
                if len(kpub) > 0 and len(sha256) == 32 and sha256 == h.digest() and len(out_sha256) == 0 and len(out_kpub) == 0:
                    if found == False:
                        out_sha256 = sha256
                        out_kpub = kpub
                        found = True
                if b.to_bytes(1, byteorder='little') == b'\x01':
                    read_cipher = True

                read_kpub = False
                read_sha256 = True
                sha256 = b''
                kpub = b''
            
            if read_sha256 == True and len(sha256) == 32:
                read_sha256 = False
                read_kpub = True

            
            
    return out_sha256, out_kpub, cipher_b


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

    sha256, kpub, cipher_b = get_kpub_sha256(input_bytes[:-256], get_bytes_from_file(my_ciph_pub_key))

    print(len(sha256))
    print(len(kpub))
    print(len(cipher_b))
    print(cipher_b)

    if len(sha256) < 1 or len(kpub) < 1 or len(cipher_b) < 1:
        print("Public key not found")
        sys.exit(1)



    # Decryption of the symmetric key
    priv_key = RSA.importKey(get_bytes_from_file(my_ciph_priv_key))
    pkcs1 = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)
    dec = pkcs1.decrypt(kpub)

    #kc = dec[:32]
    #iv = dec[32:]

    #print(len(kc))
    #print(len(iv))

    # Data Decryption from kc decrypted
    # aes = AES.new(kc, AES.MODE_CBC, iv)
    # p_buffer = unpad(aes.decrypt(c_buffer), AES.block_size)

    # return p_buffer


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


def generate_decrypt_file(out_file: str, plain_text: bytes) -> None:
    '''
    Write decrypted file bytes
    '''
    try:
        with open(out_file, 'wb') as fout:
            fout.write(plain_text)
            print(f'[+]: Decryption success: {out_file}')
    except:
        print(f'[X]: Decryption error: {out_file}')


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
    group_decrypt.add_argument('sender_sign_pub', help='sender public signature key')
    
    return parser

# $ python multi_protect.py -e <input_file> <output_file> <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]
#                                   X           X               X                   X               X

# python multi_protect.py -d <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem>
#                                 X             X               X                   X               X

if __name__ == '__main__':

    args = arg_parser().parse_args()
    if 'encrypt' in args:
        # python3 multi_protect.py encryption -e ../../../plain ../../../encrypt ../../../key-pair-1/signature-1-priv.pem ../../../key-pair-1/cipher-1-pub.pem ../../../key-pair-2/cipher-2-pub.pem ../../../key-pair-3/cipher-3-pub.pem
        generate_encrypt_file(args.output_file, encrypt(args.input_file, args.my_sign_priv_key, args.my_ciph_pub_key, args.users_ciph_pub))
        sys.exit(0)
    
    elif 'decrypt' in args:
        # python3 multi_protect.py decryption -d ../../../encrypt ../../../decrypt ../../../key-pair-2/cipher-2-priv.pem ../../../key-pair-2/cipher-2-pub.pem ../../../key-pair-1/signature-1-pub.pem
        print("decryption")
        generate_decrypt_file(args.output_file, decrypt(args.input_file, args.my_ciph_priv_key, args.my_ciph_pub_key, args.sender_sign_pub))
        sys.exit(0)

    print("Error")
    sys.exit(1)
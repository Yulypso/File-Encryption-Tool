# File-Encryption-Tool

## Author

[![Linkedin: Thierry Khamphousone](https://img.shields.io/badge/-Thierry_Khamphousone-blue?style=flat-square&logo=Linkedin&logoColor=white&link=https://www.linkedin.com/in/tkhamphousone/)](https://www.linkedin.com/in/tkhamphousone)

<br/>

## Introduction 

This project is about creating a tool that encrypt/decrypt files using AES-256-CBC and HMAC signature (digest mode SHA256) from [PyCryptodome library](https://pycryptodome.readthedocs.io/en/latest/src/introduction.html).

---
<br/>

## Getting started


### Symmetric encryption

```sh
❯ python3 protect_symmetric.py -h
usage: protect_symmetric.py [-h] (-e | -d) -i FIN -o FOUT password

AES-256-CBC encryption & HMAC-SHA256 integrity check tool

positional arguments:
  password             Secret password

optional arguments:
  -h, --help           show this help message and exit
  -e, --encrypt        Encryption mode
  -d, --decrypt        Decryption mode
  -i FIN, --in FIN     input file
  -o FOUT, --out FOUT  output file
```

For instance: 
```sh
❯ python3 protect_symmetric.py -e -i ../../../plain -o ../../../encrypt password

[+]: Encryption success: ../../../encrypt
```

```sh
❯ python3 protect_symmetric.py -d -i ../../../encrypt -o ../../../decrypt password

[+]: Decryption success: ../../../decrypt
```

<br/>

### Asymmetric encryption

Generate private/public keys for sender and receiver.

```sh
❯ openssl genrsa 2122 > rsa-1-priv.pem
❯ openssl rsa -pubout -in rsa-1-priv.pem > rsa-1-pub.pem

❯ openssl genrsa 2122 > rsa-2-priv.pem
❯ openssl rsa -pubout -in rsa-2-priv.pem > rsa-2-pub.pem
```
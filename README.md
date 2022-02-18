# File-Encryption-Tool

## Author

[![Linkedin: Thierry Khamphousone](https://img.shields.io/badge/-Thierry_Khamphousone-blue?style=flat-square&logo=Linkedin&logoColor=white&link=https://www.linkedin.com/in/tkhamphousone/)](https://www.linkedin.com/in/tkhamphousone)

<br/>

## Introduction 

This project is about creating a tool that encrypt/decrypt files using AES-256-CBC and HMAC signature (digest mode SHA256) from [PyCryptodome library](https://pycryptodome.readthedocs.io/en/latest/src/introduction.html).

---
<br/>

## Getting started

```sh
❯ pip install pycryptodome
```

### Symmetric encryption

Usage: 
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
❯ cd ./FileEncryptionTool/src/cryptography/Symmetric
❯ python3 protect_symmetric.py -e -i ../../../plain -o ../../../encrypt password

[+]: Encryption success: ../../../encrypt
```

```sh
❯ cd ./FileEncryptionTool/src/cryptography/Symmetric
❯ python3 protect_symmetric.py -d -i ../../../encrypt -o ../../../decrypt password

[+]: Decryption success: ../../../decrypt
```

---

<br/>

### Asymmetric encryption

#### Generating keys

Generate private/public keys for sender and receiver.

Using generate-keys.sh script: 
```sh
❯ cd ./FileEncryptionTool
❯ ./generate-keys.sh 
```

Manually: 
```sh
❯ cd ./FileEncryptionTool
❯ openssl genrsa 2122 > rsa-1-priv.pem
❯ openssl rsa -pubout -in rsa-1-priv.pem > rsa-1-pub.pem

❯ openssl genrsa 2122 > rsa-2-priv.pem
❯ openssl rsa -pubout -in rsa-2-priv.pem > rsa-2-pub.pem
```

Usage: 
```sh
usage: protect_asymmetric.py [-h] (-e | -d) -priv PRIVATE_KEY -pub PUBLIC_KEY -i FIN -o FOUT

AES-256-CBC symmetric encryption, RSA asymmetric encryption & RSA-SHA256 PKCS#1 PSS signature integrity check tool

optional arguments:
  -h, --help            show this help message and exit
  -e, --encrypt         Encryption mode
  -d, --decrypt         Decryption mode
  -priv PRIVATE_KEY, --private PRIVATE_KEY
                        private key
  -pub PUBLIC_KEY, --public PUBLIC_KEY
                        public key
  -i FIN, --in FIN      input file
  -o FOUT, --out FOUT   output file
```

For instance:
```sh
❯ cd ./FileEncryptionTool/src/cryptography/Asymmetric
❯ python3 protect_asymmetric.py -e -i ../../../plain -o ../../../encrypt -priv ../../../rsa-1-priv.pem -pub ../../../rsa-2-pub.pem

[+]: Encryption success: ../../../encrypt
```

```sh
❯ cd ./FileEncryptionTool/src/cryptography/Asymmetric
❯ python3 protect_asymmetric.py -d -i ../../../encrypt -o ../../../decrypt -priv ../../../rsa-2-priv.pem -pub ../../../rsa-1-pub.pem

[+]: The signature is authentic.
[+]: Decryption success: ../../../decrypt
```

---

<br/>

### Multi User Encryption

#### Generating keys

Using generate-keys.sh script: 
```sh
# Generates 3 key-pairs
❯ cd ./FileEncryptionTool
❯ ./generate-keys.sh 4
```

General usage: 
```sh
usage: multi_protect.py [-h] {e,d} ...

Multi user encryption tool: AES-256-CBC symmetric encryption, RSA asymmetric encryption & RSA-SHA256 PKCS#1 PSS signature integrity check

positional arguments:
  {e,d}       Multi User Encryption Mode
    e         Encryption Mode
    d         Decryption Mode

optional arguments:
  -h, --help  show this help message and exit
```

Encryption module usage: 
```sh
usage: multi_protect.py e [-h] input_file output_file my_sign_priv_key my_ciph_pub_key users_ciph_pub [users_ciph_pub ...]

positional arguments:
  input_file        plain input file
  output_file       encrypted output file
  my_sign_priv_key  my private signature key
  my_ciph_pub_key   my public cipher key
  users_ciph_pub    users public cipher key

optional arguments:
  -h, --help        show this help message and exit
```

Decryption module usage:
```sh
usage: multi_protect.py d [-h] input_file output_file my_ciph_priv_key my_ciph_pub_key sender_sign_pub

positional arguments:
  input_file        encrypted input file
  output_file       decrypted output file
  my_ciph_priv_key  my private cipher key
  my_ciph_pub_key   my public cipher key
  sender_sign_pub   sender public signature key

optional arguments:
  -h, --help        show this help message and exit
```

For instance:
- Encryption of the file: plain
- Sender using: key-pair-1/
- Receiver using: key-pair-1/, key-pair-2/, key-pair-3/
```sh
❯ cd ./FileEncryptionTool/src/cryptography/Multi-User-Encryption
❯ python3 multi_protect.py e ../../../plain ../../../encrypt ../../../key-pair-1/signature-1-priv.pem ../../../key-pair-1/cipher-1-pub.pem ../../../key-pair-2/cipher-2-pub.pem ../../../key-pair-3/cipher-3-pub.pem ../../../key-pair-3/cipher-3-pub.pem

[+]: Encryption success: ../../../encrypt
```

**Authorized**
- Decryption of the file: encrypt
- Receiver using: key-pair-2/ and signature-1-pub.pem (Sender public signature key)
```sh
❯ cd ./FileEncryptionTool/src/cryptography/Multi-User-Encryption
❯ python3 multi_protect.py d ../../../encrypt ../../../decrypt ../../../key-pair-2/cipher-2-priv.pem ../../../key-pair-2/cipher-2-pub.pem ../../../key-pair-1/signature-1-pub.pem

[+]: The signature is authentic.
[+]: Decryption success: ../../../decrypt
```

**Unauthorized: not in recipient users**
- decryption of the file: encrypt
- Receiver using: key-pair-4/ and signature-1-pub.pem (Sender public signature key)
```sh
❯ cd ./FileEncryptionTool/src/cryptography/Multi-User-Encryption
❯ python3 multi_protect.py d ../../../encrypt ../../../decrypt ../../../key-pair-4/cipher-4-priv.pem ../../../key-pair-4/cipher-4-pub.pem ../../../key-pair-1/signature-1-pub.pem

[+]: The signature is authentic.
[!]: Public key not found
```

> User n°4 cannot decrypt the message because he is not in the list of recipient users even if the signature is authentic.


**Unauthorized: signature is not authentic**
- decryption of the file: encrypt
- Receiver using: key-pair-4/ and signature-1-pub.pem (Sender public signature key)
```sh
❯ cd ./FileEncryptionTool/src/cryptography/Multi-User-Encryption
❯ python3 multi_protect.py d ../../../encrypt ../../../decrypt ../../../key-pair-3/cipher-3-priv.pem ../../../key-pair-3/cipher-3-pub.pem ../../../key-pair-4/signature-4-pub.pem

[!]: The signature is not authentic.
```

> User n°3 cannot verify the integrity of the message since the signature is not authentic. 

> The program does not allow the decryption of the message if the signature is not authentic although the message can be correctly decrypted in our case because user 3 is among the recipients. 
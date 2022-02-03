import sys
import binascii
from Crypto.Hash import SHA256


def sha256(file: str, chunk_size: int) -> bytes:
    h = SHA256.new(data=None)

    with open(file, encoding="utf8") as f:
        data = f.read(chunk_size).encode()
        while data:
            h.update(data)
            data = f.read(chunk_size).encode()
    return(h.digest())


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('required 1 argument')
        sys.exit(1)

    hash = sha256(sys.argv[1], 1024)
    print(hash)
    print(binascii.hexlify(hash).decode('utf-8'))

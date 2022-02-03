import sys
from Crypto.Random import get_random_bytes


def generate_key(length: int) -> bytes: return get_random_bytes(length)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('required 1 argument')
        sys.exit(1)

    print(generate_key(int(sys.argv[1])))

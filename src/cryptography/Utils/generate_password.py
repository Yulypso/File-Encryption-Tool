#!/usr/bin/env python3

'''
Author: Thierry Khamphousone @Yulypso
Date: 03/02/2022
'''

import sys
import string
from Crypto.Random.random import choice


def generate_password(len_pass: int, char_list=tuple(string.ascii_letters + string.digits + string.punctuation)) -> str: return "".join(
    choice(char_list) for _ in range(len_pass))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('required 1 argument')
        sys.exit(1)

    print(generate_password(int(sys.argv[1]), tuple(
        string.ascii_letters + string.digits + string.punctuation)))
    sys.exit(0)

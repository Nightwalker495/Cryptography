#!/usr/bin/env python3
# Author: Milan Ondrasovic <milan.ondrasovic@gmail.com>
# Wordlist generator
#
# This file is path of CryptoTools (Encryption/Decryption Tools)
# related to the cryptography classes.

import sys
import base64


def main():
    for line in filter(lambda x: len(x.strip()) > 0, sys.stdin.readlines()):
        login, salt, base64_passwd = line.strip().split(':')
        passwd_hash = int.from_bytes(base64.b64decode(base64_passwd), 'big')
        print('{0}:{1}:{2:032x}'.format(login, salt, passwd_hash))

    return 0


if __name__ == '__main__':
    sys.exit(main())

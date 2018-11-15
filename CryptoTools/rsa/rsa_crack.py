#!/usr/bin/env python3
# Author: Milan Ondrasovic <milan.ondrasovic@gmail.com>
# RSA cipher decryption
#
# This file is path of CryptoTools (Encryption/Decryption Tools)
# related to the cryptography classes.

import sys
import click


class ModUtils:

    @staticmethod
    def mod_inv(a, m):
        if a < 0:
            a = m - a
        g, x, y = ModUtils.__egcd(a, m)
        if g != 1:
            raise ValueError('modular inverse does not exist')
        return x % m

    @staticmethod
    def __egcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            g, y, x = ModUtils.__egcd(b % a, a)
            return g, x - (b // a) * y, y


class RsaCracker:

    def __init__(self, e_coef, n_coef, cipher_msg):
        self.__e_coef = e_coef
        self.__n_coef = n_coef
        self.__cipher_msg = cipher_msg

    def decrypt_message(self):
        return 0


@click.command()
@click.argument('e_coef', help='(`E`, n) coefficient of public key')
@click.argument('n_coef', help='(e, `N`) coefficient of public key')
@click.argument('cipher_val', help='encrypted message in integer format')
def main(e_coef, n_coef, cipher_msg):
    rsa_cracker = RsaCracker(int(e_coef), int(n_coef), int(cipher_msg))
    orig_msg = rsa_cracker.decrypt_message()
    print('''
    PUBLIC KEY =\t({}, {})
    CIPHER MESSAGE =\t{}
    ORIGINAL MESSAGE =\t{}'''.format(e_coef, n_coef, cipher_msg, orig_msg))
    return 0


if __name__ == '__main__':
    sys.exit(main())

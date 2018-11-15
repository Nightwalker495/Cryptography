#!/usr/bin/env python3
# Author: Milan Ondrasovic <milan.ondrasovic@gmail.com>
# RSA cipher decryption
#
# This file is path of CryptoTools (Encryption/Decryption Tools)
# related to the cryptography classes.

import os
import sys
import click
import sympy


class RsaCracker:

    def __init__(self, e_coef, n_coef, cipher_msg):
        self.__e_coef = e_coef
        self.__n_coef = n_coef
        self.__cipher_msg = cipher_msg

    def decrypt_message(self):
        factors = self.__find_prime_factors(self.__n_coef)
        if len(factors) != 2:
            raise ValueError('The N coefficient does not have two factors')
        phi = self.__calc_eulers_phi_for_primes(factors[0], factors[1])
        d_coef = sympy.mod_inverse(self.__e_coef, phi)
        return self.__rsa_decrypt(d_coef)

    @staticmethod
    def __calc_eulers_phi_for_primes(prime_1, prime_2):
        return (prime_1 - 1) * (prime_2 - 1)

    @staticmethod
    def __find_prime_factors(value):
        return [factor for factor, exponent in sympy.factorint(value).items()]

    def __rsa_decrypt(self, d_coef):
        return pow(self.__cipher_msg, d_coef, self.__n_coef)


@click.command()
@click.argument('e_coef')
@click.argument('n_coef')
@click.argument('cipher_msg')
def main(e_coef, n_coef, cipher_msg):
    rsa_cracker = RsaCracker(int(e_coef), int(n_coef), int(cipher_msg))
    orig_msg = rsa_cracker.decrypt_message()
    print('''PUBLIC KEY =\t\t({}, {})
CIPHER MESSAGE =\t{}
ORIGINAL MESSAGE =\t{}'''.format(e_coef, n_coef, cipher_msg, orig_msg))
    return os.EX_OK


if __name__ == '__main__':
    sys.exit(main())

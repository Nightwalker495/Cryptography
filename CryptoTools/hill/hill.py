#!/usr/bin/env python3
# Author: Milan Ondrasovic <milan.ondrasovic@gmail.com>
# Hill cipher decryption
#
# This file is path of CryptoTools (Encryption/Decryption Tools)
# related to the cryptography classes.

import sys
import click
import numpy as np


class HillCipher:

    MOD = 26

    def __init__(self, plain_text_start, cipher_text, block_size):
        if block_size < 1:
            raise ValueError('block size must be at least 1')
        if len(plain_text_start) < block_size ** 2:
            raise ValueError('insufficient number of plain text characters')
        if len(cipher_text) % 3 != 0:
            raise ValueError('cipher text len. is not a multiple of block size')

        self.__plain_text_start_ord =\
            self.convert_text_to_letter_order_vals(plain_text_start)
        self.__cipher_text_ord =\
            self.convert_text_to_letter_order_vals(cipher_text)
        self.__block_size = block_size

    def decrypt(self):
        decryption_matrix = self.__find_decryption_matrix()

        plain_text_ord = []
        blocks = self.separate_into_blocks(self.__cipher_text_ord,
                                           self.__block_size)
        for block in blocks:
            plain_text_vector = np.matmul(decryption_matrix, block)
            plain_text_vector = self.__matrix_elements_mod(plain_text_vector)

            for item in plain_text_vector:
                plain_text_ord.append(int(item))

        return self.convert_letter_order_vals_to_text(plain_text_ord)

    @staticmethod
    def convert_text_to_letter_order_vals(text):
        if not text.isalpha():
            raise ValueError('text contains a non-alpha character')
        return [HillCipher.get_letter_order(letter) for letter in text]

    @staticmethod
    def convert_letter_order_vals_to_text(order_vals):
        return ''.join(chr(val + ord('A')) for val in order_vals)

    @staticmethod
    def get_letter_order(letter):
        return ord(letter) - (ord('A') if letter.isupper() else ord('a'))

    @staticmethod
    def separate_into_blocks(data, block_size):
        for i in range(0, len(data), block_size):
            yield data[i:i + block_size]

    @staticmethod
    def mod_inv(a, m):
        if a < 0:
            a = m - a
        g, x, y = HillCipher.__egcd(a, m)
        if g != 1:
            raise ValueError('modular inverse does not exist')
        return x % m

    @staticmethod
    def __egcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            g, y, x = HillCipher.__egcd(b % a, a)
            return g, x - (b // a) * y, y

    @staticmethod
    def __matrix_mod_inverse(matrix):
        inverse, det = np.linalg.inv(matrix), np.linalg.det(matrix)
        inv_det_mul = inverse * det

        mod = HillCipher.MOD
        det_mod_inv = HillCipher.mod_inv(int(round(det)) % mod, mod)

        matrix_det_mov_inv_mul = inv_det_mul * det_mod_inv
        matrix_rounded = matrix_det_mov_inv_mul.round()

        return HillCipher.__matrix_elements_mod(matrix_rounded)

    @staticmethod
    def __matrix_elements_mod(matrix):
        return np.remainder(matrix, np.full(matrix.shape, HillCipher.MOD))

    def __build_matrix_from_cipher_text(self):
        bs = self.__block_size
        matrix_size = bs ** 2
        matrix = np.zeros(shape=(matrix_size, matrix_size))

        for row_offset in range(bs):
            for i in range(matrix_size):
                row = row_offset + ((i // bs) * bs)
                col = (row_offset * bs) + (i % bs)
                matrix[row][col] = self.__cipher_text_ord[i]

        return matrix

    def __find_decryption_matrix(self):
        cipher_text_matrix = self.__build_matrix_from_cipher_text()
        cipher_text_matrix_inv = self.__matrix_mod_inverse(cipher_text_matrix)

        plain_text_ord_vector = np.array(
            self.__plain_text_start_ord[:self.__block_size ** 2])
        res_vector = np.matmul(cipher_text_matrix_inv, plain_text_ord_vector)
        res_matrix = res_vector.reshape((self.__block_size, self.__block_size))

        return self.__matrix_elements_mod(res_matrix)


@click.command()
@click.argument('plain_text_start')
@click.argument('block_size')
def main(plain_text_start, block_size):
    for line in sys.stdin.readlines():
        line_stripped = line.strip()
        hill_cipher = HillCipher(plain_text_start, line_stripped,
                                 int(block_size))

        decrypted_text = hill_cipher.decrypt()
        print('"{}" --> "{}"'.format(line_stripped, decrypted_text))

    return 0


if __name__ == '__main__':
    sys.exit(main())

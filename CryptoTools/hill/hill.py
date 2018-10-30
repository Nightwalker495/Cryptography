#!/usr/bin/env python3
# Author: Milan Ondrasovic <milan.ondrasovic@gmail.com>
# Hill cipher decryption
#
# This file is path of CryptoTools (Encryption/Decryption Tools)
# related to the cryptography classes.

import sys
import click
import numpy as np


class TrigramHillCipher:

    MATRIX_SIZE = 9
    TRIGRAM_SIZE = 3
    MOD = 26

    def __init__(self, plain_text_start):
        self.__plain_text_start = plain_text_start

    def decrypt(self, cipher_text):
        cipher_text_order_vals = \
            self.convert_text_to_letter_order_vals(cipher_text)
        cipher_text_trigrams = list(self.separate_into_groups(
            cipher_text_order_vals, self.TRIGRAM_SIZE))

        decryption_matrix = self.__find_decryption_matrix(cipher_text_trigrams)

        plain_text_order_vals = []
        for trigram in cipher_text_trigrams:
            plain_text = np.matmul(decryption_matrix, trigram)
            plain_text = np.remainder(plain_text, np.full(plain_text.shape, 26))
            for p in plain_text:
                plain_text_order_vals.append(int(p))

        return self.convert_letter_order_vals_to_text(plain_text_order_vals)

    @staticmethod
    def convert_text_to_letter_order_vals(text):
        if not text.isalpha():
            raise ValueError('text contains a non-alpha character')
        return [
            ord(letter) - (ord('A') if letter.isupper() else ord('a'))
            for letter in text
        ]

    @staticmethod
    def convert_letter_order_vals_to_text(order_vals):
        return ''.join(chr(val + ord('A')) for val in order_vals)

    @staticmethod
    def separate_into_groups(data, group_size):
        for i in range(0, len(data), group_size):
            yield data[i:i + group_size]

    @staticmethod
    def matrix_mod_inverse(matrix, mod):
        inverse, det = np.linalg.inv(matrix), np.linalg.det(matrix)
        inv_det_mul = inverse * det

        det_mod_inv = TrigramHillCipher.mod_inv(int(round(det)) % mod, mod)

        matrix_det_mov_inv_mul = inv_det_mul * det_mod_inv
        matrix_rounded = matrix_det_mov_inv_mul.round()

        size = TrigramHillCipher.MATRIX_SIZE
        return np.remainder(matrix_rounded, np.full((size, size), mod))

    @staticmethod
    def mod_inv(a, m):
        if a < 0:
            a = m - a
        g, x, y = TrigramHillCipher.__egcd(a, m)
        if g != 1:
            raise ValueError('modular inverse does not exist')
        return x % m

    @staticmethod
    def __egcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            g, y, x = TrigramHillCipher.__egcd(b % a, a)
            return g, x - (b // a) * y, y

    @staticmethod
    def __build_matrix_from_ciphertext(trigram_1, trigram_2, trigram_3):
        size = TrigramHillCipher.MATRIX_SIZE
        matrix = np.zeros(shape=(size, size))

        t = trigram_1
        matrix[0][0], matrix[0][1], matrix[0][2] = t[0], t[1], t[2]
        matrix[1][3], matrix[1][4], matrix[1][5] = t[0], t[1], t[2]
        matrix[2][6], matrix[2][7], matrix[2][8] = t[0], t[1], t[2]

        t = trigram_2
        matrix[3][0], matrix[3][1], matrix[3][2] = t[0], t[1], t[2]
        matrix[4][3], matrix[4][4], matrix[4][5] = t[0], t[1], t[2]
        matrix[5][6], matrix[5][7], matrix[5][8] = t[0], t[1], t[2]

        t = trigram_3
        matrix[6][0], matrix[6][1], matrix[6][2] = t[0], t[1], t[2]
        matrix[7][3], matrix[7][4], matrix[7][5] = t[0], t[1], t[2]
        matrix[8][6], matrix[8][7], matrix[8][8] = t[0], t[1], t[2]

        return matrix

    def __find_decryption_matrix(self, cipher_text_trigrams):
        cipher_text_matrix = self.__build_matrix_from_ciphertext(
            cipher_text_trigrams[0], cipher_text_trigrams[1],
            cipher_text_trigrams[2])
        cipher_text_matrix_inv = self.matrix_mod_inverse(cipher_text_matrix,
                                                         self.MOD)

        p = self.convert_text_to_letter_order_vals(
            self.__plain_text_start)
        plain_text_vector = np.array([p[0], p[1], p[2], p[3], p[4], p[5],
                                      p[6], p[7], p[8]])

        res_vector = np.matmul(cipher_text_matrix_inv, plain_text_vector)
        res_matrix = np.array([
            [res_vector[0], res_vector[1], res_vector[2]],
            [res_vector[3], res_vector[4], res_vector[5]],
            [res_vector[6], res_vector[7], res_vector[8]]
        ])
        return np.remainder(res_matrix, np.full((3, 3), 26))


@click.command()
@click.argument('plain_text_start')
def main(plain_text_start):
    hill_cipher = TrigramHillCipher(plain_text_start)

    for line in sys.stdin.readlines():
        line_stripped = line.strip()
        decrypted_text = hill_cipher.decrypt(line_stripped)
        print('"{}" --> "{}"'.format(line_stripped, decrypted_text))

    return 0


if __name__ == '__main__':
    sys.exit(main())

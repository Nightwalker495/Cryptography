#!/usr/bin/evn python3
# Author: Milan Ondrasovic <milan.ondrasovic@gmail.com>
# Vigenere cipher decryption
#
# This file is path of CryptoTools (Encryption/Decryption Tools)
# related to the cryptography classes.

import sys
import click
import collections


class ItemProbabilityCalc:

    @staticmethod
    def init_from_item_prob_file(file_path):
        with open(file_path) as in_file:
            table = {line[0]: float(line[2:])
                     for line in in_file.readlines() if len(line) > 0}
            return ItemProbabilityCalc(**table)

    @staticmethod
    def init_from_text(text):
        char_count_dict = collections.defaultdict(int)
        total_count = 0

        for char in text:
            char_count_dict[char] += 1
            total_count += 1

        table = {char: (count / float(total_count))
                 for char, count in char_count_dict.items()}
        return ItemProbabilityCalc(**table)

    def __init__(self, **kwargs):
        self.__item_probability_map = {}

        for item, prob in kwargs.items():
            self.__set_probability(item, prob)

    def __getitem__(self, item):
        if item not in self.__item_probability_map:
            return 0.0
        return self.__item_probability_map[item]

    def __contains__(self, item):
        return item in self.__item_probability_map

    def calc_item_prob_diff(self, other):
        diff = 0
        for char, prob in self.__item_probability_map:
            if char not in other:
                continue
            diff = abs(prob - other[char])
        return diff

    def __set_probability(self, item, probability):
        if 0.0 <= probability <= 1.0:
            self.__item_probability_map[item] = probability
        else:
            raise ValueError('probability not in range <0, 1>')


class TextStripper:

    @staticmethod
    def strip_non_alpha(text):
        return ''.join(c for c in text if c.isalpha())


class VigenereCipher:

    @staticmethod
    def decrypt(text, password):
        if not password.isalpha():
            raise ValueError('password must contain only a-zA-Z letters')
        if len(password) < 1:
            raise ValueError('password must not be empty')

        output = ''
        password_pos = 0
        for char in text:
            decrypted_char = char
            if char.isalpha():
                decrypted_char = VigenereCipher.\
                    __decrypt_char(char, password[password_pos])
                password_pos = (password_pos + 1) % len(password)
            output += decrypted_char

        return output

    @staticmethod
    def __decrypt_char(char_text, char_password):
        char_shift, password_shift = ord('A'), ord('A')

        if char_text.islower():
            char_shift = ord('a')
        if char_password.islower():
            password_shift = ord('a')

        char_num = ord(char_text) - char_shift
        password_num = ord(char_password) - password_shift
        res_num = (char_num + (26 - password_num)) % 26

        return chr(res_num + char_shift)


@click.command()
@click.argument('min_passwd_len')
@click.argument('max_passwd_len')
@click.argument('lang')
def main(min_passwd_len, max_passwd_len, lang):
    return 0


if __name__ == '__main__':
    sys.exit(main())

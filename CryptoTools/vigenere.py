#!/usr/bin/env python3
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
    def init_from_iterable(text):
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

    def __iter__(self):
        return iter(self.__item_probability_map.items())

    def calc_item_prob_diff(self, other):
        diff = 0
        for char, prob in self.__item_probability_map.items():
            if char in other:
                diff += abs(prob - other[char])
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


class VigenereCipherBruteForceEngine:

    def __init__(self, text, password_len, theoretical_letter_prob):
        if len(text) < password_len:
            raise ValueError('text length is smaller than password length')
        if min(len(text), password_len) < 1:
            raise ValueError('text and password must not be empty')

        self.__text = text
        self.__password_len = password_len
        self.__theoretical_letter_prob = theoretical_letter_prob

    @staticmethod
    def __separate_text_into_subtexts(text, subtexts_no):
        subtexts = []
        for i in range(subtexts_no):
            subtexts.append(''.join(
                [text[j] for j in range(i, len(text), subtexts_no)]))
        return subtexts

    def run(self):
        password = self.__find_min_prob_diff_password()
        print('***** Password: {0}'.format(password))
        print(VigenereCipher.decrypt(self.__text, password))

    def __find_min_prob_diff_password(self):
        password = ''
        stripped_text = TextStripper.strip_non_alpha(self.__text)
        for subtext in self.__separate_text_into_subtexts(stripped_text,
                                                          self.__password_len):
            password += self.__brute_force_subtext_caesar_cipher(subtext)
        return password

    def __brute_force_subtext_caesar_cipher(self, subtext):
        min_prob_password_char, min_prob_diff = 0, float('inf')

        for i in range(ord('A'), ord('Z') + 1):
            password_char = chr(i)

            decrypted_subtext = VigenereCipher.decrypt(subtext, password_char)
            item_prob_calc = ItemProbabilityCalc.init_from_iterable(
                decrypted_subtext)

            prob_diff = self.__theoretical_letter_prob. \
                calc_item_prob_diff(item_prob_calc)

            if prob_diff < min_prob_diff:
                min_prob_password_char, min_prob_diff = password_char, prob_diff

        return min_prob_password_char


#@click.command()
#@click.argument('min_password_len')
#@click.argument('max_password_len')
#@click.argument('lang')
def main(min_password_len, max_password_len, lang):
    with open('./input/vigenere/text_test_small_4_passwd_len.txt') as in_file:
        content = in_file.read()
        theoretical_letter_prob = ItemProbabilityCalc.init_from_item_prob_file(
            './resources/sk_letter_probabilities.txt')
        brute_force_engine = VigenereCipherBruteForceEngine(content, 4,
                                                            theoretical_letter_prob)
        brute_force_engine.run()

    return 0


if __name__ == '__main__':
    sys.exit(main(4, 4, 'sk'))

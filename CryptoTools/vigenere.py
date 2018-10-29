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
        return self.__find_min_prob_diff_password(self.__password_len)

    def __find_min_prob_diff_password(self, password_len):
        password = ''
        stripped_text = TextStripper.strip_non_alpha(self.__text)
        for subtext in self.__separate_text_into_subtexts(stripped_text,
                                                          password_len):
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


class InvalidCmdArgsError(Exception):

    def __init__(self, msg):
        super().__init__(msg)


class LangInfoProvider:

    __SUPPORTED_LANGS = {'en': './resources/en_letter_probabilities.txt',
                         'sk': './resources/sk_letter_probabilities.txt'}

    @staticmethod
    def get_supported_langs():
        return iter(LangInfoProvider.__SUPPORTED_LANGS.keys())

    @staticmethod
    def get_theoretical_prob_file_for_lang(lang):
        lang_lower = lang.strip().lower()
        if lang_lower in LangInfoProvider.__SUPPORTED_LANGS:
            return LangInfoProvider.__SUPPORTED_LANGS[lang_lower]
        raise ValueError('unsupported language')


def check_cmd_args_validity(brute_force, password, password_len_range):
    if brute_force is None:
        if password is None:
            raise InvalidCmdArgsError('brute force or decryption mode '
                                      'must be activated')
    else:
        if password_len_range is None:
            raise InvalidCmdArgsError('password length range must be specified '
                                      'in brute force mode')


def process_decryption(text, password):
    print('*** Text decrypted by password \'{}\''.format(password))
    print(VigenereCipher.decrypt(text, password))


def parse_password_len_range(password_len_range):
    sep_pos = password_len_range.index(',')
    if sep_pos < 0:
        raise InvalidCmdArgsError('password length range not in format a,b')
    return int(password_len_range[:sep_pos].strip()),\
           int(password_len_range[sep_pos + 1:].strip())


def process_brute_force(text, min_password_len, max_password_len):
    if min_password_len > max_password_len:
        min_password_len, max_password_len = max_password_len, min_password_len

    for lang in LangInfoProvider.get_supported_langs():
        print('### LANGUAGE = {}'.format(lang))

        theoretical_letter_prob = ItemProbabilityCalc.init_from_item_prob_file(
            LangInfoProvider.get_theoretical_prob_file_for_lang(lang))

        for password_len in range(min_password_len, max_password_len + 1):
            brute_force_engine =\
                VigenereCipherBruteForceEngine(text, password_len,
                                               theoretical_letter_prob)
            password = brute_force_engine.run()
            print('*** Brute force: [password = \'{}\'; length = {}]'.format(
                password, password_len))
            print(VigenereCipher.decrypt(text, password))


@click.command()
@click.argument('input_file_path')
@click.option('--brute-force', is_flag=True, help='activates brute-force mode')
@click.option('--password', help='decrypts the text using this password')
@click.option('--password-len-range',
              help='password length range in format a,b')
def main(input_file_path, brute_force, password, password_len_range):
    try:
        check_cmd_args_validity(brute_force, password, password_len_range)
    except InvalidCmdArgsError as e:
        print('error: {}'.format(str(e)), file=sys.stderr)
        return 1

    with open(input_file_path) as in_file:
        text = in_file.read()

        if password is not None:
            process_decryption(text, password)

        if brute_force is not None:
            min_len, max_len = parse_password_len_range(password_len_range)
            process_brute_force(text, min_len, max_len)

    return 0


if __name__ == '__main__':
    sys.exit(main())

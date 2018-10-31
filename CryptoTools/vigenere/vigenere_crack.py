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
                    decrypt_char(char, password[password_pos])
                password_pos = (password_pos + 1) % len(password)
            output += decrypted_char

        return output

    @staticmethod
    def find_single_letter_password(encrypted_letter,
                                    expected_decrypted_letter):
        start, end = ord('A'), ord('Z')
        if encrypted_letter.islower():
            start, end = ord('a'), ord('z')

        for password in range(start, end + 1):
            password_letter = chr(password)
            if VigenereCipher.decrypt_char(encrypted_letter,
                                           password_letter) == \
                    expected_decrypted_letter:
                return password_letter
        raise ValueError('impossible parameters for the encryption')

    @staticmethod
    def encrypt_char(char, password):
        def transform(char_num, password_num):
            return char_num + password_num
        return VigenereCipher.__transform_char_by_password(char, password,
                                                           transform)

    @staticmethod
    def decrypt_char(char, password):
        def transform(char_num, password_num):
            return char_num + (26 - password_num)
        return VigenereCipher.__transform_char_by_password(char, password,
                                                           transform)

    @staticmethod
    def __transform_char_by_password(char, password, transform_func):
        char_shift, password_shift = ord('A'), ord('A')

        if char.islower():
            char_shift = ord('a')
        if password.islower():
            password_shift = ord('a')

        char_num = ord(char) - char_shift
        password_num = ord(password) - password_shift
        res_num = transform_func(char_num, password_num) % 26

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

    __SUPPORTED_LANGS = {'en': '../resources/en_letter_probabilities.txt',
                         'sk': '../resources/sk_letter_probabilities.txt'}

    @staticmethod
    def get_supported_langs():
        return iter(LangInfoProvider.__SUPPORTED_LANGS.keys())

    @staticmethod
    def get_theoretical_prob_file_for_lang(lang):
        lang_lower = lang.strip().lower()
        if lang_lower in LangInfoProvider.__SUPPORTED_LANGS:
            return LangInfoProvider.__SUPPORTED_LANGS[lang_lower]
        raise ValueError('unsupported language')


def check_cmd_args_validity(brute_force, password, expected_content_file_path):
    if (brute_force is None) and (password is None) and\
            (expected_content_file_path is None):
            raise InvalidCmdArgsError('brute force, decryption or password '
                                      'correction mode must be activated')
    if (expected_content_file_path is not None) and (password is None):
        raise InvalidCmdArgsError('password must be specified in '
                                  'correction mode')


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

    sep = ''
    for lang in LangInfoProvider.get_supported_langs():
        theoretical_letter_prob = ItemProbabilityCalc.init_from_item_prob_file(
            LangInfoProvider.get_theoretical_prob_file_for_lang(lang))

        for password_len in range(min_password_len, max_password_len + 1):
            brute_force_engine =\
                VigenereCipherBruteForceEngine(text, password_len,
                                               theoretical_letter_prob)
            password = brute_force_engine.run()
            print(sep, end='')
            print('\t[PASSWORD = \'{}\' | LENGTH = {} | LANGUAGE = {}]'.format(
                password, password_len, lang))
            print(VigenereCipher.decrypt(text, password))
            sep = ('#' * 80) + '\n'


def process_password_correction(encrypted_text, decrypted_text_expected,
                                password):
    corrected_password = list(password)
    pos = 0

    for enc_char, decr_char in zip(encrypted_text, decrypted_text_expected):
        if pos >= len(password):
            break

        if enc_char.isalpha() and enc_char.isalpha():
            corrected_password[pos] = VigenereCipher.\
                find_single_letter_password(enc_char, decr_char)
        elif not enc_char.isalpha() and not decr_char.isalpha():
            continue
        else:
            raise ValueError('encrypted and expected texts do not match '
                             'in terms of letter positions')
        pos += 1

    print('### Corrected password: {}'.format(''.join(corrected_password)))


@click.command()
@click.option('--brute-force', help='brute-force mode for password length '
                                    'range in format a,b')
@click.option('--password', help='decrypts the text using this password')
@click.option('--expected-content-file-path',
              help='expected content file (this mode repairs the password)')
def main(brute_force, password, expected_content_file_path):
    try:
        check_cmd_args_validity(brute_force, password,
                                expected_content_file_path)
    except InvalidCmdArgsError as e:
        print('error: {}'.format(str(e)), file=sys.stderr)
        return 1

    text = sys.stdin.read()

    if password is not None and expected_content_file_path is None:
        process_decryption(text, password)

    if brute_force is not None:
        min_len, max_len = parse_password_len_range(brute_force)
        process_brute_force(text, min_len, max_len)

    if expected_content_file_path is not None:
        with open(expected_content_file_path) as in_file:
            process_password_correction(text, in_file.read(), password)

    return 0


if __name__ == '__main__':
    sys.exit(main())

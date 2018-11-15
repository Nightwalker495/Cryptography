#!/usr/bin/env python3
# Author: Milan Ondrasovic <milan.ondrasovic@gmail.com>
# MD5 hash cracker
#
# This file is path of CryptoTools (Encryption/Decryption Tools)
# related to the cryptography classes.

import os
import sys
import click
import base64
import hashlib


class PasswordNotFoundException(Exception):
    pass


class Md5Decrypter:

    def __init__(self, password_hash_base64, salt,
                 password_len_min, password_len_max,
                 use_alpha_lower=False,
                 use_alpha_upper=False, use_digits=False, wordlist_path=None):
        self.__target_password_hash = self.__base64_str_to_int(
            password_hash_base64)
        self.__salt = salt

        self.__password_len_min = password_len_min
        self.__password_len_max = password_len_max
        self.__validate_password_len()

        self.__allowed_chars = self.__build_allowed_chars_list(use_alpha_lower,
                                                               use_alpha_upper,
                                                               use_digits)
        self.__wordlist_path = wordlist_path

    def decrypt_brute_force(self):
        password = None
        if self.__wordlist_path is not None:
            password = self.__decrypt_brute_force_wordlist()
            if password is not None:
                return password

        if len(self.__allowed_chars) > 0:
            password = self.__decrypt_brute_force_all_password_lengths()

        if password is None:
            raise PasswordNotFoundException()
        return password

    @staticmethod
    def __base64_str_to_int(base64_str):
        b64_bytes = base64.b64decode(base64_str)
        return int.from_bytes(b64_bytes, 'big')

    @staticmethod
    def __build_allowed_chars_list(use_alpha_lower=False, use_alpha_upper=False,
                                   use_digits=False):
        def chars_range(min_char, max_char):
            return map(chr, range(ord(min_char), ord(max_char) + 1))

        allowed_chars = []

        if use_alpha_lower:
            allowed_chars += chars_range('a', 'z')
        if use_alpha_upper:
            allowed_chars += chars_range('A', 'Z')
        if use_digits:
            allowed_chars += chars_range('0', '9')

        return allowed_chars

    def __validate_password_len(self):
        if self.__password_len_min > self.__password_len_max:
            self.__password_len_min, self.__password_len_max = \
                self.__password_len_max, self.__password_len_min

    def __decrypt_brute_force_all_password_lengths(self):
        for password_len in range(self.__password_len_min,
                                  self.__password_len_max + 1):
            prev_password = [0 for _ in range(password_len)]
            password = self.__decrypt_brute_force_chars(0, prev_password)
            if password is not None:
                return password

        return None

    def __decrypt_brute_force_chars(self, curr_password_pos, password_list):
        for curr_char in self.__allowed_chars:
            password_list[curr_password_pos] = curr_char
            if curr_password_pos == len(password_list) - 1:
                password = ''.join(password_list)
                if self.__is_password_valid(password):
                    return password
            else:
                password = self.__decrypt_brute_force_chars(
                    curr_password_pos + 1, password_list)
                if password is not None:
                    return password
        return None

    def __decrypt_brute_force_wordlist(self):
        raise NotImplemented()

    def __is_password_valid(self, password):
        return self.__md5_hash(password) == self.__target_password_hash

    def __md5_hash(self, password):
        md5_hasher = hashlib.md5()
        md5_hasher.update(password.encode('utf-8'))
        md5_hasher.update(self.__salt.encode('utf-8'))
        md5_digest = md5_hasher.digest()
        return int.from_bytes(md5_digest, 'big')


def parse_password_len_range(password_len_range):
    sep_pos = password_len_range.index(',')
    if sep_pos < 0:
        raise ValueError('password length range not in format A,B')
    return int(password_len_range[:sep_pos].strip()),\
           int(password_len_range[sep_pos + 1:].strip())


@click.command()
@click.argument('login')
@click.argument('salt')
@click.argument('md5_base64_digest')
@click.option('--passwd-len', help='password length range in format A,B')
@click.option('--alpha-lower', is_flag=True, default=False,
              help='use lowercase letters')
@click.option('--alpha-upper', is_flag=True, default=False,
              help='use uppercase letters')
@click.option('--digits', is_flag=True, default=False, help='use digits')
@click.option('--wordlist-path', default=None,
              help='path to text file (line = password)')
def main(login, salt, md5_base64_digest, passwd_len, alpha_lower, alpha_upper,
         digits, wordlist_path):
    return os.EX_OK


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
# Author: Milan Ondrasovic <milan.ondrasovic@gmail.com>
# MD5 hash cracker
#
# This file is path of CryptoTools (Encryption/Decryption Tools)
# related to the cryptography classes.

import os
import abc
import sys
import base64
import hashlib
import threading
import itertools
import multiprocessing


class PasswordGenerator(abc.ABC):

    @abc.abstractmethod
    def __iter__(self):
        pass


class WordlistPasswordGenerator(PasswordGenerator):

    def __init__(self, wordlist_file_path):
        self.__passwords = None
        with open(wordlist_file_path) as wordlist_file:
            self.__passwords = [line.strip()
                                for line in wordlist_file.readlines()
                                if len(line.strip()) > 0]

    def __iter__(self):
        return iter(self.__passwords)


class StandardPasswordGenerator(PasswordGenerator):

    def __init__(self, password_len, use_alpha_lower=False,
                 use_alpha_upper=False, use_digits=False):
        self.__password_len = password_len
        self.__allowed_chars = self.__build_allowed_chars_list(use_alpha_lower,
                                                               use_alpha_upper,
                                                               use_digits)

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

    def __iter__(self):
        for password in itertools.product(self.__allowed_chars,
                                          repeat=self.__password_len):
            yield ''.join(password)


class LoginInstance:

    def __init__(self, login, password_hash_base64, salt):
        self.__login = login
        self.__password_hash_base64 = password_hash_base64
        self.__salt = salt

        self.__salt_encoded = self.__salt.encode('utf-8')
        self.__password_hash = self.__base64_str_to_int(password_hash_base64)
        self.__plain_password = None

    def __str__(self):
        password_str = 'password not known'\
            if self.__plain_password is None else self.__plain_password
        return '{} [{} | {}] --> {}'.format(self.__login,
                                            self.__password_hash_base64,
                                            self.__salt, password_str)

    @property
    def plain_password(self):
        return self.__plain_password

    @staticmethod
    def build_from_str(description_str):
        tokens = [token.strip() for token in description_str.split(':')]

        login = tokens[0]
        salt = tokens[1]
        password_hash_base64 = tokens[2]

        return LoginInstance(login, password_hash_base64, salt)

    @staticmethod
    def __base64_str_to_int(base64_str):
        return int.from_bytes(base64.b64decode(base64_str), 'big')

    def update_plain_password_if_valid(self, password):
        if self.__is_password_valid(password):
            self.__plain_password = password
            return True
        return False

    def __is_password_valid(self, password):
        return self.__md5_hash(password) == self.__password_hash

    def __md5_hash(self, password):
        md5_hasher = hashlib.md5()
        md5_hasher.update(password.encode('utf-8'))
        md5_hasher.update(self.__salt_encoded)
        return int.from_bytes(md5_hasher.digest(), 'big')


class Md5BatchDecrypter:

    def __init__(self):
        self.__password_generators = []
        self.__login_instances = []

    def add_password_generator(self, password_generator):
        self.__password_generators.append(password_generator)

    def add_login_inst(self, login_inst):
        self.__login_instances.append(login_inst)

    def run_brute_force(self):
        unprocessed_login_instances = list(self.__login_instances)

        for password_gen in self.__password_generators:
            for password in password_gen:
                if len(unprocessed_login_instances) == 0:
                    break

                password_found_positions = []
                for i, login_inst in enumerate(unprocessed_login_instances):
                    if login_inst.update_plain_password_if_valid(password):
                        password_found_positions.append(i)

                for pos in password_found_positions:
                    del unprocessed_login_instances[pos]


def read_input_as_login_instances():
    return map(lambda x: LoginInstance.build_from_str(x),
               filter(lambda x: len(x.strip()) > 0, sys.stdin))


def add_test_password_settings(md5_batch_decrypter):
    gen = StandardPasswordGenerator(4, True, True, True)
    md5_batch_decrypter.add_password_generator(gen)


def add_sem_project_password_settings(md5_batch_decrypter):
    gen = WordlistPasswordGenerator('../resources/sk_names_wordlist.txt')
    md5_batch_decrypter.add_password_generator(gen)

    gen = StandardPasswordGenerator(4, True, True, True)
    md5_batch_decrypter.add_password_generator(gen)

    gen = StandardPasswordGenerator(6, True)
    md5_batch_decrypter.add_password_generator(gen)

    gen = StandardPasswordGenerator(5, True, True, True)
    md5_batch_decrypter.add_password_generator(gen)

    gen = StandardPasswordGenerator(7, True)
    md5_batch_decrypter.add_password_generator(gen)


def print_login_instances(login_instances, status):
    print('Status: {}'.format(status))
    for login_inst in login_instances:
        print(login_inst)


def main():
    md5_batch_decrypter = Md5BatchDecrypter()
    login_instances = []
    for login_inst in read_input_as_login_instances():
        login_instances.append(login_inst)
        md5_batch_decrypter.add_login_inst(login_inst)

    add_test_password_settings(md5_batch_decrypter)
    #add_sem_project_password_settings(md5_batch_decrypter)

    md5_batch_decrypter.run_brute_force()
    print_login_instances(filter(lambda x: x.plain_password is not None,
                                 login_instances), 'SUCCESS')
    print_login_instances(filter(lambda x: x.plain_password is None,
                                 login_instances), 'FAILURE')

    return os.EX_OK


if __name__ == '__main__':
    sys.exit(main())

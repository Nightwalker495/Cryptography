#!/usr/bin/env python3
# Author: Milan Ondrasovic <milan.ondrasovic@gmail.com>
# MD5 hash cracker
#
# This file is path of CryptoTools (Encryption/Decryption Tools)
# related to the cryptography classes.

import unittest

from md5_crack import Md5Decrypter


class Md5DecrypterTest(unittest.TestCase):

    def setUp(self):
        self.__password_hash_base64 = None
        self.__salt = None
        self.__min_password_len = None
        self.__max_password_len = None
        self.__use_alpha_lower = False
        self.__use_alpha_upper = False
        self.__use_digits = False

    def test_1(self):
        self.__given_password_hash_base64_and_salt('Sn0e1BRHTkAzrCnMuGU9mw==',
                                                   '0')
        self.__given_password_len_range(3, 3)
        self.__given_use_digits()
        self.__then_orig_password_is('000')

    def test_2(self):
        self.__given_password_hash_base64_and_salt('9KjgM1x9EtmxTPbHxN3gOw==',
                                                   '123456789')
        self.__given_password_len_range(2, 2)
        self.__given_use_digits()
        self.__then_orig_password_is('95')

    def test_3(self):
        self.__given_password_hash_base64_and_salt('4QrcOUm6Wau+VuBX8g+IPg==',
                                                   '456')
        self.__given_password_len_range(2, 3)
        self.__given_use_digits()
        self.__then_orig_password_is('123')

    def test_4(self):
        self.__given_password_hash_base64_and_salt('ZRK9Q9nKpuAsmQsKgmUtyg==',
                                                   '1')
        self.__given_password_len_range(1, 3)
        self.__given_use_digits()
        self.__then_orig_password_is('1')

    def test_5(self):
        self.__given_password_hash_base64_and_salt('+pMb8xJ8o8xJjvMbgddQRA==',
                                                   '37tisic995')
        self.__given_password_len_range(3, 4)
        self.__given_use_alpha_lower()
        self.__then_orig_password_is('sona')

    def test_6(self):
        self.__given_password_hash_base64_and_salt('xz3L+7+AfvxNGDNdASUkWQ==',
                                                   '1aB2')
        self.__given_password_len_range(4, 4)
        self.__given_use_alpha_lower()
        self.__given_use_alpha_upper()
        self.__given_use_digits()
        self.__then_orig_password_is('1aB2')

    def __given_password_hash_base64_and_salt(self, password_hash_base64, salt):
        self.__password_hash_base64 = password_hash_base64
        self.__salt = salt

    def __given_password_len_range(self, min_password_len, max_password_len):
        self.__min_password_len = min_password_len
        self.__max_password_len = max_password_len

    def __given_use_alpha_lower(self):
        self.__use_alpha_lower = True

    def __given_use_alpha_upper(self):
        self.__use_alpha_upper = True

    def __given_use_digits(self):
        self.__use_digits = True

    def __then_orig_password_is(self, expected_password):
        decrypter = Md5Decrypter(self.__password_hash_base64, self.__salt,
                                 self.__min_password_len,
                                 self.__max_password_len,
                                 self.__use_alpha_lower,
                                 self.__use_alpha_upper,
                                 self.__use_digits)
        password = decrypter.decrypt_brute_force()
        self.assertEqual(password, expected_password)

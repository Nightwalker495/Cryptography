#!/usr/bin/env python3
# Author: Milan Ondrasovic <milan.ondrasovic@gmail.com>
# RSA cipher decryption
#
# This file is path of CryptoTools (Encryption/Decryption Tools)
# related to the cryptography classes.

import unittest

from rsa_crack import RsaCracker


class RsaCrackerTest(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.__e_coef = None
        self.__n_coef = None
        self.__cipher_msg = None

    def test_1(self):
        self.__given_e_n_c(3, 55, 49)
        self.__then_m_is(14)

    def test_2(self):
        self.__given_e_n_c(7, 143, 48)
        self.__then_m_is(9)

    def test_3(self):
        self.__given_e_n_c(3, 33, 13)
        self.__then_m_is(7)

    def test_4(self):
        self.__given_e_n_c(9, 1189, 1113)
        self.__then_m_is(19)

    def __given_e_n_c(self, e_coef, n_coef, cipher_msg):
        self.__e_coef = e_coef
        self.__n_coef = n_coef
        self.__cipher_msg = cipher_msg

    def __then_m_is(self, expected_orig_msg):
        orig_msg = RsaCracker(self.__e_coef, self.__n_coef,
                              self.__cipher_msg).decrypt_message()
        self.assertEqual(orig_msg, expected_orig_msg)

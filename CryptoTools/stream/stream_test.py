#!/usr/bin/env python3
# Author: Milan Ondrasovic <milan.ondrasovic@gmail.com>
# Stream cipher decryption
#
# This file is path of CryptoTools (Encryption/Decryption Tools)
# related to the cryptography classes.

import unittest

from stream_crack import CoincidenceIndexCalc
from stream_crack import RndGen


class RndGenTest(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.__seed = None
        self.__min_val = None
        self.__max_val = None

    def test_1(self):
        self.__given_seed_and_range(0, 0, 200)
        self.__then_first_int_vals_are(42, 58, 191, 129, 172, 95, 21, 82, 88)

    def test_2(self):
        self.__given_seed_and_range(300, 30, 50)
        self.__then_first_int_vals_are(45, 32, 32, 40, 33, 35, 46, 44, 38)

    def test_3(self):
        self.__given_seed_and_range(12345, 123000, 456000)
        self.__then_first_int_vals_are(235728, 308891, 322829, 146499)

    def __given_seed_and_range(self, seed, min_val, max_val):
        self.__seed = seed
        self.__min_val = min_val
        self.__max_val = max_val

    def __then_first_int_vals_are(self, *args):
        rnd_gen = RndGen(self.__seed)
        pos = 0
        for val in args:
            gen_val = rnd_gen.next_int(self.__min_val, self.__max_val)
            self.assertEqual(val, gen_val, 'values do not match at '
                                           '{}. position'.format(pos))
            pos += 1


class CoincidenceIndexCalcTest(unittest.TestCase):

    PRECISION = 4

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.__text = None

    def test_text_1(self):
        self.__given_text('''
        UYCKTL TAERJNNJBD AUOUYGI JNNZRCRSQO H GUOCSWSRSQO QOIYRO, DRJHN
        PYOEDLDXDVPWOZHR VFGTYACE JLRWOAZRVFQQ ZUOTOC FNFLFNNJBNHV HNXAI E 
        RVNWYJV TOKCEYJV JBLQNDHQQ (TLZNGYOONH, HNLLUAAMBJ S TSMZLFXU, HGLIP, 
        ZJTPB2, ...). DRJHN PYOEDLDXDVPWOZHR DCCSIJ OS TYCSIJ NWARCE. NH NJKSOME
        TSAAUW WACFQNPHN NHVXDUM PEUSAAACA SSCE DHBNHV XJZFYJ.
        ''')
        self.__then_coinc_index_is(0.0422)

    def test_text_2(self):
        self.__given_text('''
        XUFWH NRHILFLHQWB NRLQFLGHQFLH SUH QDVOHGRYQH WHAWB. QD CDNODGH YBVOHGNX
        SRVXGWH, FL LGH R PRQRDOIDEHWLFNX SULS. SROBDOIDEHWLFNX VLIUX. SULDPH
        WHAWB VX QDSLVDQH Y VORYHQVNRP MDCBNX Y WHOHJUDIQHM DEHFHGH EHC PHGCHUB.
        SRNXVWH VD WHAWB GHVLIURYDW.
        ''')
        self.__then_coinc_index_is(0.0589)

    def __given_text(self, text):
        self.__text = text

    def __then_coinc_index_is(self, expected_coinc_index):
        coinc_index = CoincidenceIndexCalc.calc_coinc_index(self.__text)
        self.assertAlmostEqual(coinc_index, expected_coinc_index,
                               self.PRECISION)
#!/usr/bin/evn python3
# Author: Milan Ondrasovic <milan.ondrasovic@gmail.com>
# Vigenere cipher decryption
#
# This file is path of CryptoTools (Encryption/Decryption Tools)
# related to the cryptography classes.

import abc
import sys
import collections


class LetterProbabilityAccessor(abc.ABC):

    def __init__(self):
        self.__letter_probability_dict = {}

    def __getitem__(self, item):
        item_upper = item.upper()
        if item_upper not in self.__letter_probability_dict:
            return 0.0
        return self.__letter_probability_dict[item_upper]

    def calc_letter_prob_diff(self, other):
        pass

    def _set_probability(self, letter, probability):
        self.__letter_probability_dict[letter.upper()] = probability


class TheoreticalLetterProbAccessor(LetterProbabilityAccessor):

    @staticmethod
    def build_from_file(file_path):
        with open(file_path) as in_file:
            table = {line[0]: float(line[2:])
                     for line in in_file.readlines() if len(line) > 0}
            return TheoreticalLetterProbAccessor(**table)

    def __init__(self, **kwargs):
        super().__init__()

        for letter, prob in kwargs.items():
            self._set_probability(letter, prob)


class SampleLetterProbAccessor(LetterProbabilityAccessor):

    def __init__(self, text):
        super().__init__()
        self.__init_letters_count(text)

    def __init_letters_count(self, text):
        letter_count_dict = collections.defaultdict()
        total_count = 0

        for c in text:
            if not c.isalpha():
                continue
            letter_count_dict[c.upper()] += 1
            total_count += 1

        for letter, count in letter_count_dict.items():
            self._set_probability(letter, float(count) / float(total_count))


def main():
    return 0


if __name__ == '__main__':
    sys.exit(main())

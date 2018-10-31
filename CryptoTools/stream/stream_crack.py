#!/usr/bin/env python3
# Author: Milan Ondrasovic <milan.ondrasovic@gmail.com>
# Stream cipher decryption
#
# This file is path of CryptoTools (Encryption/Decryption Tools)
# related to the cryptography classes.

import sys
import math
import click
import threading
import collections


class RndGen:

    ADD_COEF = 45989
    MUL_COEF = 84589
    MOD_COEF = 217728

    def __init__(self, seed):
        if (seed < 0) or (seed >= self.MOD_COEF):
            raise ValueError('seed not in range <{}; {}>'.
                             format(0, self.MOD_COEF))

        self.__seed = seed

    @staticmethod
    def get_max_seed():
        return RndGen.MOD_COEF - 1

    def next_int(self, lower, upper):
        return int(self.next_double(lower, upper))

    def next_double(self, lower, upper):
        return lower + (self.__gen_next() * (upper - lower))

    def __gen_next(self):
        self.__seed = ((self.MUL_COEF * self.__seed) + self.ADD_COEF) %\
                      self.MOD_COEF
        return float(self.__seed) / float(self.MOD_COEF)


class CoincidenceIndexCalc:

    @staticmethod
    def calc_coinc_index(text):
        if len(text) < 2:
            raise ValueError('text length is not at least 2')

        letter_count_all_pairs = 0
        letter_counts = []
        total_letter_count =\
            CoincidenceIndexCalc.__calc_letter_counts(text, letter_counts)

        for count in letter_counts:
            letter_count_all_pairs += (count * (count - 1)) / 2

        total_pairs_no = (total_letter_count * (total_letter_count - 1)) / 2
        return float(letter_count_all_pairs) / float(total_pairs_no)

    @staticmethod
    def __calc_letter_counts(text, letter_counts):
        letter_count_dict = collections.defaultdict(int)
        total_count = 0

        for char in text:
            if char.isalpha():
                letter_count_dict[char] += 1
                total_count += 1

        for count in letter_count_dict.values():
            letter_counts.append(count)

        return total_count


class ResultsCollector:

    def __init__(self):
        self.__thread_lock = threading.Lock()
        self.__results = []

    def add_result(self, result):
        with self.__thread_lock:
            self.__results.append(result)

    def get_top_results(self, target_coinc_index, max_results_no):
        with self.__thread_lock:
            self.__results.sort(key=lambda t: abs(t[1] - target_coinc_index))
            count = min(len(self.__results), max_results_no)

            return [item[0] for item in self.__results[:count]]


class StreamCipherCrackerThread(threading.Thread):

    LETTERS_NO = 26

    def __init__(self, cipher_text, results_collector, seed_min, seed_max):
        super().__init__()

        if seed_min > seed_max:
            seed_min, seed_max = seed_max, seed_min

        self.__cipher_text = cipher_text
        self.__results_collector = results_collector
        self.__seed_min = seed_min
        self.__seed_max = seed_max

    def run(self):
        for seed in range(self.__seed_min, self.__seed_max + 1):
            rnd_gen = RndGen(seed)
            plain_text = self.__decrypt_text(rnd_gen)
            coinc_index = CoincidenceIndexCalc.calc_coinc_index(plain_text)
            self.__results_collector.add_result((plain_text, coinc_index))

    @staticmethod
    def __decrypt_letter(letter, password_ord):
        shift = ord('A') if letter.isupper() else ord('a')
        letter_ord = ord(letter) - shift
        letters_no = StreamCipherCrackerThread.LETTERS_NO
        decrypted_letter_ord = (letter_ord + (letters_no - password_ord)) % \
                               letters_no
        return chr(decrypted_letter_ord + shift)

    def __decrypt_text(self, rnd_gen):
        text = ''

        for char in self.__cipher_text:
            decrypted_char = char
            if char.isalpha():
                password_ord = rnd_gen.next_int(0, self.LETTERS_NO)
                decrypted_char = self.__decrypt_letter(char, password_ord)
            text += decrypted_char

        return text


class StreamCipherCracker:

    THREADS_NO = 4
    TARGET_COINC_INDEX = 0.06027

    def __init__(self, cipher_text, best_candidates_no):
        if best_candidates_no < 0:
            raise ValueError('no. of best candidates must not be negative')

        self.__cipher_text = cipher_text
        self.__best_candidates_no = best_candidates_no

    def decrypt(self):
        results_collector = ResultsCollector()
        self.__brute_force_possible_seeds(results_collector)
        return results_collector.get_top_results(self.TARGET_COINC_INDEX,
                                                 self.__best_candidates_no)

    @staticmethod
    def build_intervals(min_val, max_val, intervals_no):
        step = int(math.ceil((max_val - min_val) / intervals_no))
        for val in range(min_val, max_val, step):
            a, b = val, min(max_val, (val + step - 1))
            if b == max_val - 1:
                b += 1
            yield a, b

    def __brute_force_possible_seeds(self, results_collector):
        threads = []

        for min_seed, max_seed in self.build_intervals(0, RndGen.get_max_seed(),
                                                       self.THREADS_NO):
            thread = StreamCipherCrackerThread(self.__cipher_text,
                                               results_collector,
                                               min_seed, max_seed)
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()


@click.command()
@click.argument('best_candidates_no')
def main(best_candidates_no):
    cipher_text = sys.stdin.read()
    cipher_cracker = StreamCipherCracker(cipher_text, int(best_candidates_no))

    sep = ''
    for result in cipher_cracker.decrypt():
        print(sep, end='')
        print(result)
        sep = ('*' * 80) + '\n'

    return 0


if __name__ == '__main__':
    sys.exit(main())

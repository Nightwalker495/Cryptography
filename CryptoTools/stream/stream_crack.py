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
import multiprocessing


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


class DecryptionResult:

    def __init__(self, text, coinc_index, rnd_gen_seed):
        self.__text = text
        self.__coinc_index = coinc_index
        self.__rnd_gen_seed = rnd_gen_seed

    @property
    def coinc_index(self):
        return self.__coinc_index

    def __str__(self):
        return '[Coincidence index = {0:.8f}; Seed = {1}]\n{2}'.format(
            self.__coinc_index, self.__rnd_gen_seed, self.__text)


class ResultsCollector:

    def __init__(self):
        self.__thread_lock = threading.Lock()
        self.__results = []

    def add_result(self, plain_text, coinc_index, seed):
        with self.__thread_lock:
            result = DecryptionResult(plain_text, coinc_index, seed)
            self.__results.append(result)

    def get_top_results(self, target_coinc_index, max_results_no):
        with self.__thread_lock:
            self.__results.sort(key=lambda item: abs(
                item.coinc_index - target_coinc_index))
            count = min(len(self.__results), max_results_no)

            return self.__results[:count]


class StreamCipherEngine:

    LETTERS_NO = 26

    @staticmethod
    def decrypt_text(cipher_text, rnd_gen_seed):
        plain_text = ''
        rnd_gen = RndGen(rnd_gen_seed)

        for char in cipher_text:
            decrypted_char = char
            if char.isalpha():
                password_ord = rnd_gen.next_int(0,
                                                StreamCipherEngine.LETTERS_NO)
                decrypted_char = StreamCipherEngine.\
                    __decrypt_letter(char, password_ord)
            plain_text += decrypted_char

        return plain_text

    @staticmethod
    def __decrypt_letter(letter, password_ord):
        shift = ord('A') if letter.isupper() else ord('a')
        letter_ord = ord(letter) - shift
        letters_no = StreamCipherEngine.LETTERS_NO
        decrypted_letter_ord = (letter_ord + (letters_no - password_ord)) % \
                               letters_no
        return chr(decrypted_letter_ord + shift)


class StreamCipherCrackerThread(threading.Thread):

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
            plain_text = StreamCipherEngine.decrypt_text(self.__cipher_text,
                                                         seed)
            coinc_index = CoincidenceIndexCalc.calc_coinc_index(plain_text)
            self.__results_collector.add_result(plain_text, coinc_index, seed)


class StreamCipherCracker:

    TARGET_COINC_INDEX = 0.06027

    def __init__(self, cipher_text):
        self.__cipher_text = cipher_text

    def decrypt_brute_force(self, best_candidates_no=100):
        if best_candidates_no < 0:
            raise ValueError('no. of best candidates must not be negative')
        results_collector = ResultsCollector()
        self.__brute_force_possible_seeds(results_collector)
        return results_collector.get_top_results(self.TARGET_COINC_INDEX,
                                                 best_candidates_no)

    def decrypt_for_seed(self, seed):
        return StreamCipherEngine.decrypt_text(self.__cipher_text, seed)

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

        threads_num = multiprocessing.cpu_count()
        for min_seed, max_seed in self.build_intervals(0, RndGen.get_max_seed(),
                                                       threads_num):
            thread = StreamCipherCrackerThread(self.__cipher_text,
                                               results_collector,
                                               min_seed, max_seed)
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()


@click.command()
@click.option('--best-candidates-no', default='200',
              help='no. of best candidates to show (brute force mode)')
@click.option('--seed', help='decrypts the text using seed (no brute force)')
def main(best_candidates_no, seed):
    cipher_text = sys.stdin.read()
    cipher_cracker = StreamCipherCracker(cipher_text)

    if seed is not None:
        print(cipher_cracker.decrypt_for_seed(int(seed)))
    else:
        sep = ''
        results = cipher_cracker.decrypt_brute_force(int(best_candidates_no))
        for result in results:
            print(sep, end='')
            print(result)
            sep = ('*' * 80) + '\n'

    return 0


if __name__ == '__main__':
    sys.exit(main())

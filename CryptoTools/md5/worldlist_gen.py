#!/usr/bin/env python3
# Author: Milan Ondrasovic <milan.ondrasovic@gmail.com>
# Wordlist generator
#
# This file is path of CryptoTools (Encryption/Decryption Tools)
# related to the cryptography classes.

import sys
import click
import unidecode


def read_file_as_lower_and_sorted(input_file_path):
    with open(input_file_path) as in_file:
        return sorted(list(set(unidecode.unidecode(line).strip().lower()
                               for line in in_file.readlines()
                               if len(line.strip()) > 0)))


def generate_wordlist(input_file_path, output_file_path):
    with open(output_file_path, 'w') as out_file:
        for line in read_file_as_lower_and_sorted(input_file_path):
            out_file.write(line + '\n')

            for i in range(len(line)):
                text_before = '' if i == 0 else line[:i]
                upper_letter = line[i].upper()
                text_after = '' if i == len(line) - 1 else line[i + 1:]
                line_transformed = text_before + upper_letter + text_after
                out_file.write(line_transformed + '\n')


@click.command()
@click.argument('input_file_path')
@click.argument('output_file_path')
def main(input_file_path, output_file_path):
    generate_wordlist(input_file_path, output_file_path)
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/bin/bash

python3 vigenere.py --password $(cat ./assignment_4/password_found.txt) --expected-content-file-path ./assignment_4/expected_text.txt < ../input/vigenere/text4_enc.txt

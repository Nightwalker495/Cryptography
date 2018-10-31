#!/bin/bash

python3 vigenere_crack.py --password $(cat ./assignment_4/password_found.txt) --expected-content-file-path ./assignment_4/expected_text.txt < ./assignment_4/text4_enc.txt

#!/bin/bash

python3 vigenere.py --password $(cat ./assignment_4/password_corrected.txt) < ../input/vigenere/text4_enc.txt > ./assignment_4/plain_text.txt

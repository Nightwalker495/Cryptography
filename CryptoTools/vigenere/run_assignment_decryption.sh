#!/bin/bash

python3 vigenere_crack.py --password $(cat ./assignment_4/password_corrected.txt) < ./assignment_4/text4_enc.txt > ./assignment_4/plain_text.txt

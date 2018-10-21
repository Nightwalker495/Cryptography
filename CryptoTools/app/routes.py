#!/usr/bin/evn python3
# Author: Milan Ondrasovic <milan.ondrasovic@gmail.com>
#
# This file is path of CryptoTools (Encryption/Decryption Tools)
# related to the cryptography classes.

from app import app


@app.route('/')
@app.route('/index')
def index():
    return "Hello, World!"

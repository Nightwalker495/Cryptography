#!/usr/bin/evn python3
# Author: Milan Ondrasovic <milan.ondrasovic@gmail.com>
#
# This file is path of CryptoTools (Encryption/Decryption Tools)
# related to the cryptography classes.

from flask import Flask

app = Flask(__name__)

from app import routes
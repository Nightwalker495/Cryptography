#!/bin/bash

g++ -std=c++0x -O3 -s -pedantic -Wall -Wextra md5_cracker.cpp -o md5_cracker -lcrypto -lm

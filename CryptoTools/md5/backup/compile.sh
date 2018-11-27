#!/bin/bash

cython --embed md5_crack.py -o md5_crack.c
gcc -I/usr/include/python3.6m -I/usr/include/x86_64-linux-gnu/python3.6m -std=c99 -O3 -s ./md5_crack.c -o md5_crack_bin -lpython3.6m

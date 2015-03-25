# -*- mode: python; coding: utf-8 -*-
#
# Copyright (c) 2015 Andrej Antonov <polymorphm@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

assert str is not bytes

import struct
import itertools

base64_alphabet = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

def crypt_base64_decode(s):
    assert isinstance(s, str)
    
    if len(s) != 86:
        raise ValueError
    
    hash_list = [0] * 64
    
    def split_24bit(start, n, b2, b1, b0):
        tmp = 0
        
        for i in range(start, start + n):
            value = base64_alphabet.index(s[i])
            tmp |= value << 6 * (i - start)
        
        if b0 is not None:
            hash_list[b0] = tmp & 0xff
        if b1 is not None:
            hash_list[b1] = tmp >> 8 & 0xff
        if b2 is not None:
            hash_list[b2] = tmp >> 16 & 0xff
    
    split_24bit(0, 4, 0, 21, 42)
    split_24bit(4, 4, 22, 43, 1)
    split_24bit(8, 4, 44, 2, 23)
    split_24bit(12, 4, 3, 24, 45)
    split_24bit(16, 4, 25, 46, 4)
    split_24bit(20, 4, 47, 5, 26)
    split_24bit(24, 4, 6, 27, 48)
    split_24bit(28, 4, 28, 49, 7)
    split_24bit(32, 4, 50, 8, 29)
    split_24bit(36, 4, 9, 30, 51)
    split_24bit(40, 4, 31, 52, 10)
    split_24bit(44, 4, 53, 11, 32)
    split_24bit(48, 4, 12, 33, 54)
    split_24bit(52, 4, 34, 55, 13)
    split_24bit(56, 4, 56, 14, 35)
    split_24bit(60, 4, 15, 36, 57)
    split_24bit(64, 4, 37, 58, 16)
    split_24bit(68, 4, 59, 17, 38)
    split_24bit(72, 4, 18, 39, 60)
    split_24bit(76, 4, 40, 61, 19)
    split_24bit(80, 4, 62, 20, 41)
    split_24bit(84, 2, None, None, 63)
    
    hash_b = bytes(hash_list)
    
    return hash_b

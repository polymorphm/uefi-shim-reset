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

import crypt
import base64
import struct
import os
import stat
from . import crypt_base64

EFI_VAR_PATH_TPL = '/sys/firmware/efi/efivars/{}-605dab50-e046-4300-abb6-3dd810dd8b23'
MOK_AUTH_VAR_PATH = EFI_VAR_PATH_TPL.format('MokAuth')

EFI_REGULAR_ATTR = b'\x07\x00\x00\x00'

class UefiShimResetError(Exception):
    pass

def pw_crypt_t(salt_b, hash_b):
    # this function was written from original ``pw_crypt_t`` declaration
    #       https://github.com/lcp/mokutil/blob/0.3.0/src/password-crypt.h
    
    return struct.pack(
        '=HQH32s128s',
        4, # SHA512_BASED
        5000,
        len(salt_b),
        salt_b,
        hash_b,
    )

def uefi_shim_reset(password):
    crypt_str = crypt.crypt(password, salt=crypt.mksalt(method=crypt.METHOD_SHA512))
    crypt_list = crypt_str.split(sep='$')
    
    if len(crypt_list) != 4 or crypt_list[0] != '' or crypt_list[1] != '6':
        raise UefiShimResetError('unexpected crypt result')
    
    salt_b64 = crypt_list[2]
    hash_b64 = crypt_list[3]
    
    salt_b = salt_b64.encode()
    hash_b = crypt_base64.crypt_base64_decode(hash_b64)
    
    pw_crypt_b = pw_crypt_t(salt_b, hash_b)
    
    with open(MOK_AUTH_VAR_PATH, mode='wb') as fd:
        os.chmod(fd.fileno(), stat.S_IRUSR | stat.S_IWUSR)
        fd.write(EFI_REGULAR_ATTR + pw_crypt_b)

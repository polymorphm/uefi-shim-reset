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

import argparse
import sys
import os
import getpass
from . import uefi_shim_reset

PASSWORD_ENVIRON_NAME = 'UEFI_SHIM_RESET_PASSWORD'

def main():
    parser = argparse.ArgumentParser(
        description='utility for making request to reset UEFI MOK',
    )
    
    args = parser.parse_args()
    
    if PASSWORD_ENVIRON_NAME in os.environ:
        password = os.environ[PASSWORD_ENVIRON_NAME]
    else:
        password = getpass.getpass(prompt='Enter new password for reset: ')
        re_password = getpass.getpass(prompt='Retype new password for reset: ')
        
        if re_password != password:
            print('Sorry, passwords do not match', file=sys.stderr)
            
            exit(code=2)
    
    uefi_shim_reset.uefi_shim_reset(password)

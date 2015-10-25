#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
import sys
import os
from core.pyversion import version
def check():
    if 'linux' in sys.platform or 'darwin' == sys.platform:
        os.system('clear')
    elif 'win32' == sys.platform or 'win64' == sys.platform:
        os.system('cls')
    else:
        sys.exit('Sorry, This version of software just could be run on linux/osx/windows.')
    if version() is 2 or version() is 3:
        pass
    else:
        sys.exit('Your python version is not supported!')
    return
def os_name():
	return sys.platform
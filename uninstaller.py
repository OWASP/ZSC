#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
import os
import sys
from core import start
from core import color
if 'linux' in sys.platform:
	os.system('clear')
else:
	sys.exit(color.color('red')+'Sorry, This version of software just could be run on linux.'+color.color('reset'))
start.zcr()
print color.color('green')+'Removing Files'+color.color('white')
os.system('rm -rf /usr/share/zcr_shellcoder /usr/bin/zsc')
print color.color('green')+'Files Removed!'+color.color('white')
start.sig()

#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
__version__ = '1.0.2'
__key__ = 'SKIP'
__release_date__ = '2015 June 21'
__author__ = 'Ali Razmjoo'
import time
import sys
import os
from time import strftime,gmtime
from core import start
from core import argv_control
from lib import analyser

if sys.platform == 'win' or sys.platform == 'win32' or sys.platform == 'win64':
	clearing = 'cls' 
else:
	clearing = 'clear'
os.system(clearing)

def main():
	'''
	main function of ZCR Shellcoder
	'''
	if argv_control.exist() is not True:
		process = start.start()
		sys.exit(0)
	if argv_control.exist() is True:
		process_check = False
		if argv_control.check() is True:
			process_check = True
			analyser.do(argv_control.run())
			start.sig()
		if process_check is False:
			start.inputcheck()
	
	
if __name__ == "__main__":
    main()

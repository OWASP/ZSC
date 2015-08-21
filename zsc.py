#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
import time
import sys
import os
from time import strftime,gmtime
from core import start
from core import argv_control
from lib import analyser
if 'linux' in sys.platform:
	os.system('clear')
else:
	sys.exit('Sorry, This version of software just could be run on linux.')
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

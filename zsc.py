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
from core.compatible import check
def main(): #main function
	'''
	main function of ZCR Shellcoder
	'''
	if argv_control.exist() is not True: #if execute without any argv
		start.start() #show start page and exit
	else:
		if argv_control.check() is True: #check argv, if entered accurately
			analyser.do(argv_control.run()) #go for generating
			start.sig() #print software signature and exit
		else:
			start.inputcheck()
if __name__ == "__main__":
	check() #check os and python version if compatible
	main() #execute main function

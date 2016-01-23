#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
import sys
import os
from core.compatible import *
from core import run
from core.start import logo
exec(compile(open( str(os.path.dirname(os.path.abspath(__file__)).replace('\\','/')) + '/core/commands.py', "rb").read(), str(os.path.dirname(os.path.abspath(__file__)).replace('\\','/')) + '/core/commands.py', 'exec'))
def main():
	''' Main Fucntion '''
	logo() #zsc logo
	run.engine(commands) #run engine
	
if __name__ == "__main__":
	check() #check os and python version if compatible
	main() #execute main function
#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
import sys
from core import compatible
from core import run
from core.start import logo
execfile('core/commands.py')
def main():
	''' Main Fucntion '''
	logo() #zsc logo
	run.engine(commands) #run engine
	
if __name__ == "__main__":
	compatible.check() #check os and python version if compatible
	main() #execute main function

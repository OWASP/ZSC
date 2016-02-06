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
def version():
    return int(sys.version_info.major)
def check():
	if 'linux' in sys.platform or 'darwin' in sys.platform:
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
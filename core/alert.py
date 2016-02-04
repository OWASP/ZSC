#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
import sys
from core import color
def info(content):
	sys.stdout.write(color.color('yellow')+'[+] '+color.color('green')+content+color.color('reset'))
	return
def write(content):
	sys.stdout.write(content)
	return
def warn(content):
	sys.stdout.write(color.color('red')+'[!] '+color.color('yellow')+content+color.color('reset'))
	return
def error(content):
	sys.stdout.write(content)
	return
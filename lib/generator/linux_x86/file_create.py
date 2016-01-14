#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
shellcode template used : http://shell-storm.org/shellcode/files/shellcode-57.php
'''
import binascii
from core import stack
from core import template
def run(filename,content):
	content = binascii.b2a_hex(content.replace('[space]',' '))
	l = len(content) -1
	n = 0
	c = '\\x'
	for word in content:
		c += word
		n+=1
		if n is 2:
			n = 0
			c += '\\x'
	c = c[:-2]
	command = 'echo -e "%s" > %s' %(str(c),str(filename)) 
	return template.sys(stack.generate(command.replace('[space]',' '),'%ecx','string'))

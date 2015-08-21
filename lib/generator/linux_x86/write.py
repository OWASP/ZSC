#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
import binascii
from core import stack
from core import template
def run(path_file,content):
	null = len(path_file) % 4
	if null is not 0:
		null = ''
	if null is 0:
		null = 'xor %ebx,%ebx\npush %ebx\n'
	return template.write(str(null),stack.generate(str(path_file),'%ebx','string'),stack.generate(str(content),'%ecx','string'),stack.generate(str(len(content)),'%edx','int'))

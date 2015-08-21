#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
from core import stack
from core import template
def run(file_to_perm,perm_num):
	return template.chmod(stack.generate(perm_num,'%ecx','int'),stack.generate(file_to_perm,'%ebx','string'))

	

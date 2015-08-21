#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
from core import stack
from core import template
def run(file_to_exec):
	return template.exc(stack.generate(file_to_exec,'%ebx','string'))

#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
shellcode template used : http://shell-storm.org/shellcode/files/shellcode-57.php
'''
from core import stack
from core import template
def run(command):
	command = command.replace('[space]',' ')
	if int(len(command)) < 5:
		command = str(command) + '[space]&&[space]echo[space]1[space]>[space]/dev/null' #bypass a bug in here, fix later
	#bug in line 12 & 13, check later 
	return template.sys(stack.generate(command.replace('[space]',' '),'%ecx','string'))

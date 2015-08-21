#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
def start(shellcode,job):
	if 'chmod(' in job:	
		shellcode = 'N' + shellcode
	if 'dir_create(' in job:
		shellcode = 'N' + shellcode
	if 'download_execute(' in job:
		shellcode = 'N' + shellcode
	if 'download(' in job:
		shellcode = 'N' + shellcode
	if 'exec(' in job:
		shellcode = 'N' + shellcode
	if 'file_create(' in job:
		shellcode = 'N' + shellcode
	if 'script_executor(' in job:
		shellcode = 'N' + shellcode
	if 'system(' in job:
		shellcode = 'N' + shellcode
	if 'write(' in job:
		shellcode = 'N' + shellcode
	return shellcode

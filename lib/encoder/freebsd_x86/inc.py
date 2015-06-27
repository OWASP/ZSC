#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
def start(shellcode,job):
	if 'chmod(' in job:	
		print 'This encoding feature is not available yet, please wait for next versions.'
	if 'dir_create(' in job:
		print 'This encoding feature is not available yet, please wait for next versions.'
	if 'download_execute(' in job:
		print 'This encoding feature is not available yet, please wait for next versions.'
	if 'download(' in job:
		print 'This encoding feature is not available yet, please wait for next versions.'
	if 'exc(' in job:
		print 'This encoding feature is not available yet, please wait for next versions.'
	if 'file_create(' in job:
		print 'This encoding feature is not available yet, please wait for next versions.'
	if 'script_executor(' in job:
		print 'This encoding feature is not available yet, please wait for next versions.'
	if 'system(' in job:
		print 'This encoding feature is not available yet, please wait for next versions.'
	if 'write(' in job:
		print 'This encoding feature is not available yet, please wait for next versions.' 
	return shellcode
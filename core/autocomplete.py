#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
import os
import sys

try:
	from .module.getch.getch import getch
	from .core.compatible import version
	from .core.alert import *
except:
	from module.getch.getch import getch
	from core.compatible import version
	from core.alert import *
def complete(data,commands):
	if data == '':
		write('zsc> ')
	if version() is 2:
		key = str(getch()) 
		if key == '\x09':
			key = ''
			found = []
			for command in commands:
				if data in command[:len(data)]:
					found.append(command)
			if len(found) is 0:
				pass
			elif len(found) is 1:
				return found[0]
			else:
				toprint = '\n'
				for command in found:
					toprint += '%-13s'%command
				write(toprint+'\n')
		return str(data) + key
	if version is 3:
		return str(data) + str(getch().decode('utf-8'))
def check(data,commands):
	PASS = False
	for command in commands:
		if data == command:
			PASS = True
	return PASS
def _get_command(command_path,commands):
	command = ''
	while True:
		if '\x03' in command or '\x04' in command:
			sys.exit(0)
		elif len(command) is not 0 and command[-1] in '\x08':
			command = command[:-2]
			write('\b'*150+command+' ')
			sys.stdout.flush()
		elif '\x0d' in command:
			if len(command) is 1:
				command = ''
				print('\n')
			else:
				if check(command[:-1],commands) is True:
					return command
				else:
					warn('Command not found!\n')
					command = ''
		else:
			if '\xe0' in command:
				command = ''
				write('\b'*150+command+'  ')
				sys.stdout.flush()
				warn('Please don\'t use up/down/left/right keys\n')
			command = complete(command,commands)
			write('\b'*10000+command_path+'> '+command)
			sys.stdout.flush()
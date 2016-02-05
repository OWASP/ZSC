#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
import sys
import readline
import os
from core.compatible import *
from core.alert import *
from core.commands import *
from core.update import _update
from lib.shell_storm_api.grab import _search_shellcode
from lib.shell_storm_api.grab import _download_shellcode
from core.encode import encode_process
from core.get_input import _input
from core.opcoder import op
from core.obfuscate import obf_code
from core.autocomplete import _get_command

exec(compile(open( str(os.path.dirname(os.path.abspath(__file__)).replace('\\','/')) + '/commands.py', "rb").read(), str(os.path.dirname(os.path.abspath(__file__)).replace('\\','/')) + '/commands.py', 'exec'))
exec(compile(open( str(os.path.dirname(os.path.abspath(__file__)).replace('\\','/')) + '/start.py', "rb").read(), str(os.path.dirname(os.path.abspath(__file__)).replace('\\','/')) + '/start.py', 'exec'))

_option_replace = '''
commands = commands[command]
command_path.append(command)
'''

def getcommand(commands):
	exit_counter = 0
	backup_commands = commands
	crawler = 0
	command_path = ['zsc']
	command = ''
	while True:
		try:
			print('')
			command = _get_command('/'.join(command_path),commands)[:-1]
			if command is None:
				_lets_error
		except:
			command = ''
			warn('\nplease use "exit" or "quit" to exit software.\n')
			exit_counter += 1
		if exit_counter is 3:
			error('\nExit\n')
			sys.exit(0)
		check = True
		if command == 'exit':
			write(color.color('reset'))
			sys.exit('')
		elif command == 'shellcode':
			write('\n')
			exec(_option_replace)
		elif command == 'obfuscate':
			write('\n')
			exec(_option_replace)
		elif command == 'update':
			_update(__version__)
		elif command == 'help':
			exit_counter = 0
			_help(help)
		elif command == 'restart':
			exec(compile(open( str(os.path.dirname(os.path.abspath(__file__)).replace('\\','/')) + '/commands.py', "rb").read(), str(os.path.dirname(os.path.abspath(__file__)).replace('\\','/')) + '/commands.py', 'exec'))
		elif command == 'about':
			about()
		elif command == 'version':
			_version()
		else:
			if command != '' and check is True:
				exit_counter = 0
				write('\n')
				warn('Command not found!\n')
def engine(commands):
	''' engine function'''
	getcommand(commands)

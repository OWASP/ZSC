#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
import sys
import os
from core.compatible import *
from core.alert import *
from core.commands import *
from core.update import _update
from lib.shell_storm_api.grab import _search_shellcode
from lib.shell_storm_api.grab import _download_shellcode
from lib.shell_storm_api.grab import _grab_all
from core.encode import encode_process
from core.get_input import _input
from core.opcoder import op
from core.obfuscate import obf_code
from core.file_out import file_output
if 'linux' in sys.platform:
	import readline
elif 'darwin' in sys.platform:
	sys.path.insert(0, 'module/readline_osx')
	import readline
elif 'win32' == sys.platform or 'win64' == sys.platform:
	sys.path.insert(0, 'module/readline_windows')
	import readline
exec (compile(
	open(
		str(os.path.dirname(os.path.abspath(__file__)).replace('\\', '/')) +
		'/commands.py', "rb").read(), str(os.path.dirname(os.path.abspath(
			__file__)).replace('\\', '/')) + '/commands.py', 'exec'))
exec (compile(
	open(
		str(os.path.dirname(os.path.abspath(__file__)).replace('\\', '/')) +
		'/start.py', "rb").read(), str(os.path.dirname(os.path.abspath(
			__file__)).replace('\\', '/')) + '/start.py', 'exec'))


class autocomplete(object):
	def __init__(self, options):
		self.options = sorted(options)

	def complete(self, text, state):
		if state == 0:
			if text:
				self.matches = [s for s in self.options
								if s and s.startswith(text)]
			else:
				self.matches = self.options[:]
		try:
			return self.matches[state]
		except IndexError:
			return None


def getcommand(commands):

	backup_commands = commands
	crawler = 0
	command_path = ['zsc']
	command = ''
	while True:
		try:
			command = _input('/'.join(command_path), 'any', False)
			if command is None:
				_lets_error
		except:
			warn('interrupted by user!\nExit\n')
			sys.exit(0)
		check = True

		if command.startswith('#'): # allows for comments
			continue

		inContext = ['clear', 'help', 'about', 'version', 'back']
		for option in commands:
			if command == option and command not in inContext:
				crawler += 1
				if crawler is 1:
					commands = commands[option][1]
					command_path.append(option)
				if crawler is 2:
					if command == 'search':
						_search_shellcode(False,0)
						commands = backup_commands
						completer = autocomplete(commands)
						readline.set_completer(completer.complete)
						readline.parse_and_bind('tab: complete')
						crawler = 0
						command_path = ['zsc']
					elif command == 'download':
						_download_shellcode(False,0,'')
						commands = backup_commands
						completer = autocomplete(commands)
						readline.set_completer(completer.complete)
						readline.parse_and_bind('tab: complete')
						crawler = 0
						command_path = ['zsc']
					elif command == 'shell_storm_list':
						_grab_all()
						commands = backup_commands
						completer = autocomplete(commands)
						readline.set_completer(completer.complete)
						readline.parse_and_bind('tab: complete')
						crawler = 0
						command_path = ['zsc']
					elif command == 'generate':
						commands = commands[option]
						command_path.append(option)
					else:
						while True:
							f = []
							import os as OS
							for (dirpath, dirnames, filenames) in OS.walk('.'):
								f.extend(filenames)
								break
							completer = autocomplete(f)
							readline.set_completer(completer.complete)
							filename = _input('filename', 'any', True)
							completer = autocomplete(commands)
							readline.set_completer(completer.complete)
							try:
								content = open(filename, 'rb').read()
								break
							except:
								warn('sorry, cann\'t find file\n')
						commands = commands[option]
						command_path.append(option)
						completer = autocomplete(commands)
						readline.set_completer(completer.complete)
						readline.parse_and_bind('tab: complete')
						t = True
						while t:
							encode = _input('encode', 'any', True)
							for en in commands:
								if encode == en:
									t = False
							if t is True:
								warn('please enter a valid encode name\n')
						obf_code(option, encode, filename, content,False)
						commands = backup_commands
						completer = autocomplete(commands)
						readline.set_completer(completer.complete)
						readline.parse_and_bind('tab: complete')
						crawler = 0
						command_path = ['zsc']
				if crawler is 3:
					os = option
					commands = commands[option]
					command_path.append(option)
				if crawler is 4:
					func = option
					commands = commands[option]
					command_path.append(option)
				if crawler is 5:
					data = []
					backup_option = option
					if option != '':
						options = option.rsplit('&&')
						for o in options:
							data.append(_input(o,'any',True))
						n = 0
						write('\n')
						for o in options:
							info('%s set to "%s"\n' % (o, data[n]))
							n += 1
					run = getattr(
						__import__('lib.generator.%s.%s' % (os, func),
								   fromlist=['run']),
						'run')
					shellcode = run(data)
					write('\n')
					for encode in backup_commands['shellcode'][1]['generate'][
							os][func][backup_option]:
						info(encode + '\n')
					write('\n\n')
					info('enter encode type\n')
					completer = autocomplete(backup_commands['shellcode'][1][
						'generate'][os][func][backup_option])
					readline.set_completer(completer.complete)
					readline.parse_and_bind('tab: complete')
					try:
						encode = _input('/'.join(command_path) + "/encode_type", 'any', False)
						if encode is None:
							_lets_error
					except:
						encode = 'none'
						warn(
							'\n"none" encode selected\n')
					write('\n')
					assembly_code_or_not = _input(
						'Output assembly code?(y or n)', 'any', True)
					if assembly_code_or_not == 'y':
						assembly_code = True
					else:
						assembly_code = False
					if assembly_code is True:
						write('\n'+encode_process(encode, shellcode, os, func) + '\n\n')
					output_shellcode = _input('Output shellcode to screen?(y or n)', 'any', True)
					shellcode_op = op( encode_process(encode, shellcode, os, func), os)
					if output_shellcode == 'y':
						info('Generated shellcode is:\n' + shellcode_op +'\n\n')
					file_or_not = _input('Shellcode output to a .c file?(y or n)', 'any', True)
					if file_or_not == 'y':
						target = _input('Target .c file?', 'any', True)
						file_output(target, func, data, os, encode, shellcode, shellcode_op)
					commands = backup_commands
					completer = autocomplete(commands)
					readline.set_completer(completer.complete)
					readline.parse_and_bind('tab: complete')
					crawler = 0
					command_path = ['zsc']
				completer = autocomplete(commands)
				readline.set_completer(completer.complete)
				readline.parse_and_bind('tab: complete')
				check = False
		if command == 'exit' or command == 'quit':
			write(color.color('reset'))
			sys.exit('Exit')
		elif command == 'update':
			_update(__version__)
			commands = backup_commands
			completer = autocomplete(commands)
			readline.set_completer(completer.complete)
			readline.parse_and_bind('tab: complete')
			crawler = 0
			command_path = ['zsc']
		elif command == 'help':
			_help(help)
		elif command == 'restart':
			commands = backup_commands
			completer = autocomplete(commands)
			readline.set_completer(completer.complete)
			readline.parse_and_bind('tab: complete')
			crawler = 0
			command_path = ['zsc']
		elif command == 'about':
			about()
		elif command == 'version':
			_version()
		elif command == 'clear':
			_clear()
		elif command == 'back':
			if len(command_path) > 1:
				command_path.pop()
				commands = backup_commands
				for option in command_path:
					if option == 'zsc':
						pass
					elif option == command_path[1]:
						commands = commands[option][1]
					else:
						commands = commands[option]
				completer = autocomplete(commands)
				readline.set_completer(completer.complete)
				readline.parse_and_bind('tab: complete')
				crawler -= 1
			else:
				info('Can\'t go back from here!\n')
		else:
			if command != '' and check is True:
				info('Command not found!\n')


def engine(commands):
	''' engine function'''
	completer = autocomplete(commands)
	readline.set_completer(completer.complete)
	readline.parse_and_bind('tab: complete')
	getcommand(commands)

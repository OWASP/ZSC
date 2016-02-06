#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
import sys
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
try:
	import readline
except:
	sys.path.insert(0, 'module/readline_windows')
	import readline
	#os.chdir(os.path.join(os.path.abspath(os.path.curdir),u'..'))
exec(compile(open( str(os.path.dirname(os.path.abspath(__file__)).replace('\\','/')) + '/commands.py', "rb").read(), str(os.path.dirname(os.path.abspath(__file__)).replace('\\','/')) + '/commands.py', 'exec'))
exec(compile(open( str(os.path.dirname(os.path.abspath(__file__)).replace('\\','/')) + '/start.py', "rb").read(), str(os.path.dirname(os.path.abspath(__file__)).replace('\\','/')) + '/start.py', 'exec'))

_reset = '''
commands = backup_commands
completer = autocomplete(commands)
readline.set_completer(completer.complete)
readline.parse_and_bind('tab: complete')
crawler = 0
command_path = ['zsc']
'''
_refresh = '''
completer = autocomplete(commands)
readline.set_completer(completer.complete)
readline.parse_and_bind('tab: complete')
'''
_option_replace = '''
commands = commands[option]
command_path.append(option)
'''

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
	exit_counter = 0
	backup_commands = commands
	crawler = 0
	command_path = ['zsc']
	command = ''
	while True:
		try:
			command = _input('/'.join(command_path),'any',False)
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
		for option in commands:
			if command == option:
				crawler += 1
				if crawler is 1:
					commands = commands[option][1]
					command_path.append(option)
				if crawler is 2:
					if command == 'search':
						_search_shellcode()
						exec (_reset)
					elif command == 'download':
						_download_shellcode()
						exec (_reset)
					elif command == 'generate':
						exec(_option_replace)
					else:
						while True:
							filename = _input('filename','any',True)
							try:
								content = open(filename,'rb').read()
								break
							except:
								warn('sorry, cann\'t find file\n')
						exec(_option_replace)
						exec(_refresh)
						t = True
						while t:
							encode = _input('encode','any',True)
							for en in commands:
								if encode == en:
									t = False
							if t is True:
								warn('please enter a valid encode name\n')
						obf_code(option,encode,filename,content)
						exec (_reset)
				if crawler is 3:
					os = option
					exec(_option_replace)
				if crawler is 4:
					func = option
					exec(_option_replace)
				if crawler is 5:
					data = []
					backup_option = option
					options = option.rsplit('&&')
					for o in options:
						if version() is 2:
							data.append(raw_input('%s:'%o))
						if version() is 3:
							data.append(input('%s:'%o))
					n = 0
					write('\n')
					for o in options:
						info('%s set to "%s"\n'%(o,data[n]))
						n+=1
					run = getattr(__import__('lib.generator.%s.%s'%(os,func), fromlist=['run']), 'run')
					shellcode = run(data)
					write('\n')
					for encode in backup_commands['shellcode'][1]['generate'][os][func][backup_option]:
						info(encode+'\n')
					write('\n\n')
					info('enter encode type\n')
					completer = autocomplete(backup_commands['shellcode'][1]['generate'][os][func][backup_option])
					readline.set_completer(completer.complete)
					readline.parse_and_bind('tab: complete')
					try:
						encode = _input('zsc','any',False)
						if encode is None:
							_lets_error
					except:
						encode = 'none'
						warn('\n"none" encode selected\nplease use "exit" or "quit" to exit software.\n')
						exit_counter += 1
					if assembly_code is False:
						write('\n'+op(encode_process(encode,shellcode,os,func),os)+'\n\n')
					elif assembly_code is True:
						write('\n'+encode_process(encode,shellcode,os,func)+'\n\n')
					exec (_reset)
				exec(_refresh)
				check = False
		if command == 'exit':
			write(color.color('reset'))
			sys.exit('Exit')
		elif command == 'update':
			_update(__version__)
			exec (_reset)
		elif command == 'help':
			exit_counter = 0
			_help(help)
			exec (_reset)
		elif command == 'restart':
			exec (_reset)
		elif command == 'about':
			about()
			exec (_reset)
		elif command == 'version':
			_version()
			exec (_reset)
		else:
			if command != '' and check is True:
				exit_counter = 0
				info('Command not found!\n')
def engine(commands):
	''' engine function'''
	exec(_refresh)
	getcommand(commands)

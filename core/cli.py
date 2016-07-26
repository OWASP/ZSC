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
from core.update import _update
from lib.shell_storm_api.grab import _search_shellcode
from lib.shell_storm_api.grab import _download_shellcode
from lib.shell_storm_api.grab import _grab_all
from core.obfuscate import obf_code
from core.encode import encode_process
from core.opcoder import op
from core.file_out import file_output
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

def _cli_start(commands):
	command_check = {
	'help' : False,
	'sample' : False,
	'version' : False,
	'about' : False,
	'update' : False,
	'show-payloads' : False,
	'shell-storm' : False,
	'select-payload' : False,
	'input' : False,
	'assembly' : False,
	'output' : False,
	}
	n = 0
	for arg in sys.argv:
		if arg == '-h' or arg == '--help':
			command_check['help'] = n
		elif arg == '-e' or arg == '--samples-cmd':
			command_check['sample'] = n
		elif arg == '-v' or arg == '--version':
			command_check['version'] = n
		elif arg == '-a' or arg == '--about':
			command_check['about'] = n
		elif arg == '-u' or arg == '--update':
			command_check['update'] = n
		elif arg == '-l' or arg == '--show-payloads':
			command_check['show-payloads'] = n
		elif arg == '-s' or arg == '--shell-storm':
			command_check['shell-storm'] = n
		elif arg == '-p' or arg == '--payload':
			command_check['select-payload'] = n
		elif arg == '-i' or arg == '--input':
			command_check['input'] = n
		elif arg == '-c' or arg == '--assembly-code':
			command_check['assembly'] = n
		elif arg == '-o' or arg == '--output':
			command_check['output'] = n			
		n += 1
	if len(sys.argv) is 2:
		if command_check['help'] is not False:
			_help_cli(help_cli)
		elif command_check['about'] is not False:
			about()
		elif command_check['update'] is not False:
			_update(__version__)
		elif command_check['version'] is not False:
			_version()
		elif command_check['show-payloads'] is not False:
			warn('Note: Shellcode Payloads Sorted By OperatingSystem_Architecture/Function_Name/Encode_Name\n')
			warn('Note: Programming Languages Payloads Sorted By ProgrammingLanguagesName/Encode_Name\n')
			_show_payloads(commands,False)
		elif command_check['sample'] is not False:
			_show_samples(cmd_samples)
		else:
			warn('command not found!\n')
			_help_cli(help_cli)
		sys.exit(0)
	if len(sys.argv) is 3:
		if command_check['show-payloads'] is not False and command_check['shell-storm'] is False:
			try:
				content = sys.argv[command_check['show-payloads']+1]
			except:
				warn('command not found!\n')
				_help_cli(help_cli)
				sys.exit(0)
			search_flag = 0
			if content[0] == '*' and content[-1] == '*':
				search_flag = 1
				content = content[1:-1]
			elif content[0] == '*':
				search_flag = 2
				content = content[1:]
			elif content[-1] == '*':
				search_flag = 3
				content = content[:-1]
			elif '*' in content and content[0] != '*' and content[-1] != 0 and len(content) >= 3 and content.count('*') is 1:
				search_flag = 4
				c1 = content.rsplit('*')[0]
				c2 = content.rsplit('*')[1]
			payloads = _show_payloads(commands,True)
			if len(payloads) >= 1:
				warn('Note: Shellcode Payloads Sorted By OperatingSystem_Architecture/Function_Name/Encode_Name\n')
				warn('Note: Programming Languages Payloads Sorted By ProgrammingLanguagesName/Encode_Name\n')
				for payload in payloads:
					if search_flag is 0:
						if str(content) == payload.rsplit('/')[0]:
							info(payload+'\n')
					elif search_flag is 1:
						if str(content) in payload:
							info(payload+'\n')
					elif search_flag is 2:						
						if str(content) == payload[-len(content):]:
							info(payload+'\n')
					elif search_flag is 3:
						if str(content) == payload[:len(content)]:
							info(payload+'\n')
					elif search_flag is 4:
						if str(c1) == payload[:len(c1)] and str(c2) == payload[-len(c2):]:
							info(payload+'\n')
			else:
				warn('no payload find for your platform, to show all of payloads please use only "--show-payloads" switch\n')
				sys.exit(0)
		elif command_check['show-payloads'] is not False and command_check['shell-storm'] is not False:
			warn('Note: Shellcode Payloads Sorted By OperatingSystem_Architecture/Function_Name/Encode_Name\n')
			warn('Note: Programming Languages Payloads Sorted By ProgrammingLanguagesName/Encode_Name\n')
			_show_payloads(commands,False)
			warn('shell-storm shellcodes:\n')
			_grab_all()
		elif command_check['select-payload'] is not False:
			try:
				mypayload = sys.argv[command_check['select-payload']+1]
				os = mypayload.rsplit('/')[0]
				func = mypayload.rsplit('/')[1]
				encode = mypayload.rsplit('/')[2] 
				encode_tmp = sys.argv[2].rsplit('/')[2][:3]
				encodes = commands['shellcode'][1]['generate'][os][func]['']
			except:
				warn('command not found!\n')
				_help_cli(help_cli)
				sys.exit(0)
			payload_tmp = os+'/'+func+'/'+encode_tmp
			payload_flag = False
			for _ in _show_payloads(commands,True):
				if payload_tmp in _:
					payload_flag = True
			if payload_flag is True:
				run = getattr(
					__import__('lib.generator.%s.%s' % (os, func),
							   fromlist=['run']),
					'run')
				shellcode = run('')
				info('Generated shellcode is:\n\n' +op(encode_process(encode, shellcode, os, func),os) +
							 '\n\n')
		else:
			warn('command not found!\n')
			_help_cli(help_cli)
		sys.exit(0)
	elif len(sys.argv) is 4:
		if command_check['shell-storm'] is not False and command_check['show-payloads'] is False:
			if sys.argv[2] == 'search':
				_search_shellcode(True,sys.argv[3])
			elif sys.argv[2] == 'download':
				_download_shellcode(True,sys.argv[3],'')
			else:
				warn('command not found!\n')
				_help_cli(help_cli)
		elif command_check['shell-storm'] is not False and command_check['show-payloads'] is not False:
			try:
				content = sys.argv[command_check['show-payloads']+2]
			except:
				warn('command not found!\n')
				_help_cli(help_cli)
				sys.exit(0)
			search_flag = 0
			if content[0] == '*' and content[-1] == '*':
				search_flag = 1
				content = content[1:-1]
			elif content[0] == '*':
				search_flag = 2
				content = content[1:]
			elif content[-1] == '*':
				search_flag = 3
				content = content[:-1]
			elif '*' in content and content[0] != '*' and content[-1] != 0 and len(content) >= 3 and content.count('*') is 1:
				search_flag = 4
				c1 = content.rsplit('*')[0]
				c2 = content.rsplit('*')[1]
			payloads = _show_payloads(commands,True)
			if len(payloads) >= 1:
				warn('Note: Shellcode Payloads Sorted By OperatingSystem_Architecture/Function_Name/Encode_Name\n')
				warn('Note: Programming Languages Payloads Sorted By ProgrammingLanguagesName/Encode_Name\n')
				for payload in payloads:
					if search_flag is 0:
						if str(content) == payload.rsplit('/')[0]:
							info(payload+'\n')
					elif search_flag is 1:
						if str(content) in payload:
							info(payload+'\n')
					elif search_flag is 2:						
						if str(content) == payload[-len(content):]:
							info(payload+'\n')
					elif search_flag is 3:
						if str(content) == payload[:len(content)]:
							info(payload+'\n')
					elif search_flag is 4:
						if str(c1) == payload[:len(c1)] and str(c2) == payload[-len(c2):]:
							info(payload+'\n')
			else:
				warn('no payload find for your platform, to show all of payloads please use only "--show-payloads" switch\n')
				sys.exit(0)
		
			_search_shellcode(True,content)
		elif command_check['select-payload'] is not False and command_check['assembly'] is not False:
			try:
				mypayload = sys.argv[command_check['select-payload']+1]
				os = mypayload.rsplit('/')[0]
				func = mypayload.rsplit('/')[1]
				encode = mypayload.rsplit('/')[2] 
				encode_tmp = sys.argv[2].rsplit('/')[2][:3]
				encodes = commands['shellcode'][1]['generate'][os][func]['']
			except:
				warn('command not found!\n')
				_help_cli(help_cli)
				sys.exit(0)
			payload_tmp = os+'/'+func+'/'+encode_tmp
			payload_flag = False
			for _ in _show_payloads(commands,True):
				if payload_tmp in _:
					payload_flag = True
			if payload_flag is True:
				run = getattr(
					__import__('lib.generator.%s.%s' % (os, func),
							   fromlist=['run']),
					'run')
				shellcode = run('')
				info('Generated shellcode(Assembly) is:\n\n' +encode_process(encode, shellcode, os, func) +
							 '\n\n')
		else:
			warn('command not found!\n')
			_help_cli(help_cli)
		sys.exit(0)
	elif len(sys.argv) is 5:
		if command_check['select-payload'] is not False and command_check['input'] is not False:
			try:
				mypayload = sys.argv[command_check['select-payload']+1] 
				myinput = sys.argv[command_check['input']+1]
			except:
				warn('command not found!\n')
				_help_cli(help_cli)
				sys.exit(0)
			if len(mypayload.rsplit('/')) is 2:	
				if mypayload in _show_payloads(commands,True):
					filename = myinput
					language = mypayload.rsplit('/')[0]
					encode = mypayload.rsplit('/')[1]
					try:
						content = open(filename, 'rb').read()
					except:
						warn('sorry, cann\'t find file\n')
						sys.exit(0)
					obf_code(language, encode, filename, content,True)
			if len(mypayload.rsplit('/')) is 3:
				os = mypayload.rsplit('/')[0]
				func = mypayload.rsplit('/')[1]
				encode = mypayload.rsplit('/')[2]
				encode_tmp = mypayload.rsplit('/')[2][:3]
				data = myinput.rsplit('~~~')
				payload_tmp = os+'/'+func+'/'+encode_tmp
				payload_flag = False
				for _ in _show_payloads(commands,True):
					if payload_tmp in _:
						payload_flag = True
				if payload_flag is True:
					run = getattr(
						__import__('lib.generator.%s.%s' % (os, func),
								   fromlist=['run']),
						'run')
					shellcode = run(data)
					info('Generated shellcode is:\n\n' +op(encode_process(encode, shellcode, os, func),os) +
								 '\n\n')
				else:
					warn('no payload find, to show all of payloads please use "--show-payloads" switch\n')
					sys.exit(0)
			else:
				warn('no payload find, to show all of payloads please use "--show-payloads" switch\n')
				sys.exit(0)
		elif command_check['select-payload'] is not False and command_check['output'] is not False:
			
			try:
				mypayload = sys.argv[command_check['select-payload']+1]
				myoutput = sys.argv[command_check['output']+1]
				os = mypayload.rsplit('/')[0]
				func = mypayload.rsplit('/')[1]
				encode = mypayload.rsplit('/')[2] 
				encode_tmp = sys.argv[2].rsplit('/')[2][:3]
				encodes = commands['shellcode'][1]['generate'][os][func]['']
			except:
				warn('command not found!\n')
				_help_cli(help_cli)
				sys.exit(0)
			payload_tmp = os+'/'+func+'/'+encode_tmp
			payload_flag = False
			for _ in _show_payloads(commands,True):
				if payload_tmp in _:
					payload_flag = True
			if payload_flag is True:
				run = getattr(
					__import__('lib.generator.%s.%s' % (os, func),
							   fromlist=['run']),
					'run')
				shellcode = run('')
				shellcode_asm = encode_process(encode, shellcode, os, func)
				shellcode_op = op(encode_process(encode, shellcode, os, func),os) 
				info('Generated shellcode is:\n\n' + shellcode_op +
								 '\n\n')
				file_output(myoutput, func, '', os, encode,
										shellcode_asm, shellcode_op)		
			else:
				warn('command not found!\n')
				_help_cli(help_cli)
				sys.exit(0)	
		else:
			warn('command not found!\n')
			_help_cli(help_cli)
		sys.exit(0)	
	elif len(sys.argv) is 6:
		
		if command_check['shell-storm'] is not False and command_check['output'] is not False:
			try:
				id = sys.argv[command_check['shell-storm']+2]
				name = sys.argv[command_check['output']+1] 
			except:
				warn('command not found!\n')
				_help_cli(help_cli)
				sys.exit(0)	
			if sys.argv[2] == 'download':
				_download_shellcode(True,sys.argv[3],sys.argv[5])
			else:
				warn('command not found!\n')
				_help_cli(help_cli)
		elif command_check['select-payload'] is not False and command_check['input'] is not False and command_check['assembly'] is not False:
			try:
				myinput = sys.argv[command_check['input']+1]
				mypayload = sys.argv[command_check['select-payload']+1]
			except:
				warn('command not found!\n')
				_help_cli(help_cli)
				sys.exit(0)	
			if len(mypayload.rsplit('/')) is 2:
				if mypayload in _show_payloads(commands,True):
					filename = myinput
					language = mypayload.rsplit('/')[0]
					encode = mypayload.rsplit('/')[1]
					try:
						content = open(filename, 'rb').read()
					except:
						warn('sorry, cann\'t find file\n')
						sys.exit(0)
					obf_code(language, encode, filename, content,True)
			if len(mypayload.rsplit('/')) is 3:
				os = mypayload.rsplit('/')[0]
				func = mypayload.rsplit('/')[1]
				encode = mypayload.rsplit('/')[2]
				encode_tmp = mypayload.rsplit('/')[2][:3]
				data = myinput.rsplit('~~~')
				payload_tmp = os+'/'+func+'/'+encode_tmp
				payload_flag = False
				for _ in _show_payloads(commands,True):
					if payload_tmp in _:
						payload_flag = True
				if payload_flag is True:
					run = getattr(
						__import__('lib.generator.%s.%s' % (os, func),
								   fromlist=['run']),
						'run')
					shellcode = run(data)
					info('Generated shellcode(Assembly) is:\n\n' +encode_process(encode, shellcode, os, func) +
								 '\n\n')
				else:
					warn('no payload find, to show all of payloads please use "--show-payloads" switch\n')
					sys.exit(0)
			else:
				warn('no payload find, to show all of payloads please use "--show-payloads" switch\n')
				sys.exit(0)
		else:
			warn('command not found!\n')
			_help_cli(help_cli)
		sys.exit(0)

	elif len(sys.argv) is 7:
		if command_check['select-payload'] is not False and command_check['input'] is not False and command_check['output'] is not False:
			try:
				mypayload = sys.argv[command_check['select-payload']+1]
				myinput = sys.argv[command_check['input']+1]
				myoutput = sys.argv[command_check['output']+1]
			except:
				warn('command not found!\n')
				_help_cli(help_cli)
				sys.exit(0)
			if len(mypayload.rsplit('/')) is 2:	
				if mypayload in _show_payloads(commands,True):
					filename = myinput
					language = mypayload.rsplit('/')[0]
					encode = mypayload.rsplit('/')[1]
					try:
						content = open(filename, 'rb').read()
					except:
						warn('sorry, cann\'t find file\n')
						sys.exit(0)
					obf_code(language, encode, filename, content,True)
					warn('you can\'t define output for obfuscating module, file replaced!\n')
			elif len(mypayload.rsplit('/')) is 3:
				os = mypayload.rsplit('/')[0]
				func = mypayload.rsplit('/')[1]
				encode = mypayload.rsplit('/')[2]
				encode_tmp = mypayload.rsplit('/')[2][:3]
				data = myinput.rsplit('~~~')
				payload_tmp = os+'/'+func+'/'+encode_tmp
				payload_flag = False
				for _ in _show_payloads(commands,True):
					if payload_tmp in _:
						payload_flag = True
				if payload_flag is True:
					run = getattr(
						__import__('lib.generator.%s.%s' % (os, func),
								   fromlist=['run']),
						'run')
					shellcode = run(data)
					shellcode_asm = encode_process(encode, shellcode, os, func)
					shellcode_op = op(encode_process(encode, shellcode, os, func),os)
					info('Generated shellcode is:\n\n' + shellcode_op +
								 '\n\n')
					file_output(myoutput, func, data, os, encode,
										shellcode_asm, shellcode_op)
				else:
					warn('no payload find, to show all of payloads please use "--show-payloads" switch\n')
					sys.exit(0)
			else:
				warn('no payload find, to show all of payloads please use "--show-payloads" switch\n')
				sys.exit(0)
		else:
			warn('command not found!\n')
			_help_cli(help_cli)
		sys.exit(0)
	else:
		warn('command not found!\n')
		_help_cli(help_cli)
	sys.exit(0)
		
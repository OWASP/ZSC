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

	
	if len(sys.argv) is 2:
		if sys.argv[1] == '--help' or sys.argv[1] == '-h':
			_help_cli(help_cli)
		elif sys.argv[1] == '--about' or sys.argv[1] == '-a':
			about()
		elif sys.argv[1] == '--update' or sys.argv[1] == '-u':
			_update(__version__)
		elif sys.argv[1] == '--version' or sys.argv[1] == '-v':
			_version()
		elif sys.argv[1] == '--show-payloads' or sys.argv[1] == '-l':
			warn('Note: Shellcode Payloads Sorted By OperatingSystem_Architecture/Function_Name/Encode_Name\n')
			warn('Note: Programming Languages Payloads Sorted By ProgrammingLanguagesName/Encode_Name\n')
			_show_payloads(commands,False)
		elif sys.argv[1] == '--samples-cmd' or sys.argv[1] == '-e':
			_show_samples(cmd_samples)
		else:
			warn('command not found!\n')
			_help_cli(help_cli)
		sys.exit(0)
	elif len(sys.argv) is 3:
		if (sys.argv[1] == '--show-payloads' or sys.argv[1] == '-l') and (sys.argv[2] != '--shell-storm' and sys.argv[2] != '-s'):
			payloads = _show_payloads(commands,True)
			if len(payloads) >= 1:
				warn('Note: Shellcode Payloads Sorted By OperatingSystem_Architecture/Function_Name/Encode_Name\n')
				warn('Note: Programming Languages Payloads Sorted By ProgrammingLanguagesName/Encode_Name\n')
				for payload in payloads:
					if str(sys.argv[2]) == payload.rsplit('/')[0]:
						info(payload+'\n')
			else:
				warn('no payload find for your platform, to show all of payloads please use only "--show-payloads" switch\n')
				sys.exit(0)
		elif (sys.argv[1] == '--show-payloads' or sys.argv[1] == '-l') and (sys.argv[2] == '--shell-storm' or sys.argv[2] == '-s'):
			warn('Note: Shellcode Payloads Sorted By OperatingSystem_Architecture/Function_Name/Encode_Name\n')
			warn('Note: Programming Languages Payloads Sorted By ProgrammingLanguagesName/Encode_Name\n')
			_show_payloads(commands,False)
			warn('shell-storm shellcodes:\n')
			_grab_all()
		else:
			warn('command not found!\n')
			_help_cli(help_cli)
		sys.exit(0)
	elif len(sys.argv) is 4:
		if sys.argv[1] == '--shell-storm' or sys.argv[1] == '-s':
			if sys.argv[2] == 'search':
				_search_shellcode(True,sys.argv[3])
			elif sys.argv[2] == 'download':
				_download_shellcode(True,sys.argv[3],'')
			else:
				warn('command not found!\n')
				_help_cli(help_cli)
		else:
			warn('command not found!\n')
			_help_cli(help_cli)
		sys.exit(0)
	elif len(sys.argv) is 5:
		counter = {
		'--payload' : '',
		'--input' : '',
		}
		n = 0
		for arg in sys.argv:
			if arg == '-p' or arg == '--payload':
				try:
					counter['--payload'] = sys.argv[n+1]
				except:
					pass
			elif arg == '-i' or arg == '--input':
				try:
					counter['--input'] = sys.argv[n+1]
				except:
					pass
			n+=1
		if counter['--payload'] != '' and counter['--input'] != '':
			sys.argv[2] = counter['--payload'] 
			sys.argv[4] = counter['--input'] 
			if len(sys.argv[2].rsplit('/')) is 2:	
				if sys.argv[2] in _show_payloads(commands,True):
					filename = sys.argv[4]
					language = sys.argv[2].rsplit('/')[0]
					encode = sys.argv[2].rsplit('/')[1]
					try:
						content = open(filename, 'rb').read()
					except:
						warn('sorry, cann\'t find file\n')
						sys.exit(0)
					obf_code(language, encode, filename, content,True)
			if len(sys.argv[2].rsplit('/')) is 3:
				os = sys.argv[2].rsplit('/')[0]
				func = sys.argv[2].rsplit('/')[1]
				encode = sys.argv[2].rsplit('/')[2]
				encode_tmp = sys.argv[2].rsplit('/')[2][:3]
				data = sys.argv[4].rsplit('~~~')
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
		else:
			warn('command not found!\n')
			_help_cli(help_cli)
		sys.exit(0)

	elif len(sys.argv) is 6:
		counter = {
		'--shell-storm' : '',
		'--output' : '',
		'--assembly-code':'',
		'--payload': '',
		'--input':'',
		}
		n = 0
		for arg in sys.argv:
			if arg == '-s' or arg == '--shell-storm':
				if sys.argv[n+1] == 'download':
					try:
						counter['--shell-storm'] = sys.argv[n+2]
					except:
						pass
			elif arg == '-o' or arg == '--output':
				try:
					counter['--output'] = sys.argv[n+1]
				except:
					pass
			elif arg == '-i' or arg == '--input':
				try:
					counter['--input'] = sys.argv[n+1]
				except:
					pass
			elif arg == '-p' or arg == '--payload':
				try:
					counter['--payload'] = sys.argv[n+1]
				except:
					pass		
			elif arg == '-c' or arg == '--assembly-code':
				try:
					counter['--assembly-code'] = True
				except:
					pass
			n+=1
		if counter['--shell-storm'] != '' and counter['--output'] != '':
			sys.argv[1] = '--shell-storm'
			sys.argv[2] = 'download'
			sys.argv[3] = counter['--shell-storm']
			sys.argv[4] = '--output'
			sys.argv[5] = counter['--output']
		if counter['--payload'] != '' and counter['--input'] != '' and counter['--assembly-code'] is True:
			sys.argv[1] = '--payload'
			sys.argv[2] = counter['--payload']
			sys.argv[3] = '--input'
			sys.argv[4] = counter['--input']
			sys.argv[5] = '--assembly-code'
		if (sys.argv[1] == '--shell-storm' or sys.argv[1] == '-s') and (sys.argv[4] == '--output' or sys.argv[4] == '-o'):
			if sys.argv[2] == 'download':
				_download_shellcode(True,sys.argv[3],sys.argv[5])
			else:
				warn('command not found!\n')
				_help_cli(help_cli)
		elif (sys.argv[1] == '--payload' or sys.argv[1] == '-p') and (sys.argv[3] == '--input' or sys.argv[3] == '-i') and (sys.argv[5] == '--assembly-code' or sys.argv[5] == '-c'):
			if len(sys.argv[2].rsplit('/')) is 2:	
				if sys.argv[2] in _show_payloads(commands,True):
					filename = sys.argv[4]
					language = sys.argv[2].rsplit('/')[0]
					encode = sys.argv[2].rsplit('/')[1]
					try:
						content = open(filename, 'rb').read()
					except:
						warn('sorry, cann\'t find file\n')
						sys.exit(0)
					obf_code(language, encode, filename, content,True)
			if len(sys.argv[2].rsplit('/')) is 3:
				os = sys.argv[2].rsplit('/')[0]
				func = sys.argv[2].rsplit('/')[1]
				encode = sys.argv[2].rsplit('/')[2]
				encode_tmp = sys.argv[2].rsplit('/')[2][:3]
				data = sys.argv[4].rsplit('~~~')
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
		counter = {
		'--payload': '',
		'--output' : '',
		'--input':'',
		}
		n = 0
		for arg in sys.argv:
			if arg == '-o' or arg == '--output':
				try:
					counter['--output'] = sys.argv[n+1]
				except:
					pass
			elif arg == '-i' or arg == '--input':
				try:
					counter['--input'] = sys.argv[n+1]
				except:
					pass
			elif arg == '-p' or arg == '--payload':
				try:
					counter['--payload'] = sys.argv[n+1]
				except:
					pass		
			n+=1
		if counter['--payload'] != '' and counter['--output'] != '' and counter['--input'] != '':
			sys.argv[1] = '--payload'
			sys.argv[2] = counter['--payload']
			sys.argv[3] = '--input'
			sys.argv[4] = counter['--input']
			sys.argv[5] = '--output'
			sys.argv[6] = counter['--output']
		if (sys.argv[1] == '--payload' or sys.argv[1] == '-p') and (sys.argv[3] == '--input' or sys.argv[3] == '-i') and (sys.argv[5] == '--output' or sys.argv[5] == '-o'):
			if len(sys.argv[2].rsplit('/')) is 2:	
				if sys.argv[2] in _show_payloads(commands,True):
					filename = sys.argv[4]
					language = sys.argv[2].rsplit('/')[0]
					encode = sys.argv[2].rsplit('/')[1]
					try:
						content = open(filename, 'rb').read()
					except:
						warn('sorry, cann\'t find file\n')
						sys.exit(0)
					obf_code(language, encode, filename, content,True)
			if len(sys.argv[2].rsplit('/')) is 3:
				os = sys.argv[2].rsplit('/')[0]
				func = sys.argv[2].rsplit('/')[1]
				encode = sys.argv[2].rsplit('/')[2]
				encode_tmp = sys.argv[2].rsplit('/')[2][:3]
				data = sys.argv[4].rsplit('~~~')
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
					info('Generated shellcode is:\n\n' +op(encode_process(encode, shellcode, os, func),os) +
								 '\n\n')
					file_output(sys.argv[6], func, data, os, encode,
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
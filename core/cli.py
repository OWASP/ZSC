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
from core.obfuscate import obf_code
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
		if sys.argv[1] == '--show-payloads' or sys.argv[1] == '-l':
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
		if (sys.argv[1] == '--payload' or sys.argv[1] == '-p') and (sys.argv[3] == '--input' or sys.argv[3] == '-i'):
			if sys.argv[2] in _show_payloads(commands,True):
				if len(sys.argv[2].rsplit('/')) is 2:
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
					pass
			else:
				warn('no payload find for your , to show all of payloads please use "--show-payloads" switch\n')
				sys.exit(0)
		else:
			warn('command not found!\n')
			_help_cli(help_cli)
		sys.exit(0)
		#zsc --payload windows_x86/system --input "ls -la"
		#zsc -p linux_x86/chmod -i "/etc/passwd~~~777" 
		#zsc -p php/simple_hex -i "/path/file"
	elif len(sys.argv) is 6:
		if (sys.argv[1] == '--shell-storm' or sys.argv[1] == '-s') and (sys.argv[4] == '--output' or sys.argv[4] == '-o'):
			if sys.argv[2] == 'download':
				_download_shellcode(True,sys.argv[3],sys.argv[5])
			else:
				warn('command not found!\n')
				_help_cli(help_cli)
		else:
			warn('command not found!\n')
			_help_cli(help_cli)
		sys.exit(0)
		#zsc --payload windows_x86/system --input "ls -la" --assembly-code
		#zsc -p linux_x86/chmod -i "/etc/passwd~~~777"  -c
	
	elif len(sys.argv) is 7:
		pass
		#zsc --payload windows_x86/system --input "ls -la" --output shellcode.c
		#zsc -p linux_x86/chmod -i "/etc/passwd~~~777"  -o shellcode.c
	else:
		warn('command not found!\n')
		_help_cli(help_cli)
	sys.exit(0)
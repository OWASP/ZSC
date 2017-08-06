#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
from core.alert import *
from core.start import *
import os

assembly_code = False  #if True: show assembly code instead of shellcode

commands = {  #commands section
	'shellcode':  #shellcode main command
	['generate shellcode',
	 {'generate':  #shellcode sub command - to generate
	  {
		  'linux_x86':  #generate sub command - os name
		  {
			  'chmod': {'file_to_perm&&perm_number':
						['none', 'xor_random', 'xor_yourvalue', 'add_random',
						 'add_yourvalue', 'sub_random', 'sub_yourvalue', 'inc',
						 'inc_timesyouwant', 'dec', 'dec_timesyouwant',
						 'mix_all']},  #function of shellcode
			  'dir_create':
			  {'directory_to_create':
			   ['none', 'xor_random', 'xor_yourvalue', 'add_random',
				'add_yourvalue', 'sub_random', 'sub_yourvalue', 'inc',
				'inc_timesyouwant', 'dec', 'dec_timesyouwant',
				'mix_all']},  #function of shellcode
			  'download':
			  {'download_url&&filename':
			   ['none', 'xor_random', 'xor_yourvalue', 'add_random',
				'add_yourvalue', 'sub_random', 'sub_yourvalue', 'inc',
				'inc_timesyouwant', 'dec', 'dec_timesyouwant',
				'mix_all']},  #function of shellcode
			  'download_execute': {
				  'download_url&&filename&&command_to_execute':
				  ['none', 'xor_random', 'xor_yourvalue', 'add_random',
				   'add_yourvalue', 'sub_random', 'sub_yourvalue', 'inc',
				   'inc_timesyouwant', 'dec', 'dec_timesyouwant', 'mix_all']
			  },  #function of shellcode
			  'exec': {'file_to_execute':
					   ['none', 'xor_random', 'xor_yourvalue', 'add_random',
						'add_yourvalue', 'sub_random', 'sub_yourvalue', 'inc',
						'inc_timesyouwant', 'dec', 'dec_timesyouwant',
						'mix_all']},  #function of shellcode
			  'file_create': {'filename&&content': [
				  'none', 'xor_random', 'xor_yourvalue', 'add_random',
				  'add_yourvalue', 'sub_random', 'sub_yourvalue', 'inc',
				  'inc_timesyouwant', 'dec', 'dec_timesyouwant', 'mix_all'
			  ]},  #function of shellcode
			  'script_executor':
			  {'name_of_script&&name_of_your_script_in_your_pc&&execute_to_command':
			   ['none', 'xor_random', 'xor_yourvalue', 'add_random',
				'add_yourvalue', 'sub_random', 'sub_yourvalue', 'inc',
				'inc_timesyouwant', 'dec', 'dec_timesyouwant',
				'mix_all']},  #function of shellcode
			  'system': {'command_to_execute':
						 ['none', 'xor_random', 'xor_yourvalue', 'add_random',
						  'add_yourvalue', 'sub_random', 'sub_yourvalue',
						  'inc', 'inc_timesyouwant', 'dec', 'dec_timesyouwant',
						  'mix_all']},  #function of shellcode
			  'write': {'file_to_write&&content':
						['none', 'xor_random', 'xor_yourvalue', 'add_random',
						 'add_yourvalue', 'sub_random', 'sub_yourvalue', 'inc',
						 'inc_timesyouwant', 'dec', 'dec_timesyouwant',
						 'mix_all']},  #function of shellcode
		  },
		  'windows_x86':  #generate sub command -os name
		  {
			  'exec': {'file_to_execute':
					   ['none', 'xor_random', 'add_random',
			'sub_random', 'xor_yourvalue', 'inc',
			'dec', 'inc_timesyouwant', 'dec_timesyouwant',
			'add_yourvalue', 'sub_yourvalue']},
			  'dir_create': {'directory_to_create':
							 ['none', 'xor_random', 'add_random',
				 'sub_random', 'xor_yourvalue', 'inc',
				 'dec', 'inc_timesyouwant', 'dec_timesyouwant',
				 'add_yourvalue', 'sub_yourvalue']},
			  'create_file': {'filename&&content':
							  ['none', 'xor_random', 'add_random', 
				   'sub_random', 'xor_yourvalue', 'inc',
				   'dec', 'inc_timesyouwant', 'dec_timesyouwant',
				   'add_yourvalue', 'sub_yourvalue']},
			  'download_tofile': {'url&&filename':
								  ['none', 'xor_random', 'add_random',
					   'sub_random', 'xor_yourvalue', 'inc',
				   'dec', 'inc_timesyouwant', 'dec_timesyouwant',
				   'add_yourvalue', 'sub_yourvalue']},
			  'download_exec': {'url&&filename':
								['none', 'xor_random', 'add_random',
					 'sub_random', 'xor_yourvalue', 'inc',
				 'dec', 'inc_timesyouwant', 'dec_timesyouwant',
				 'add_yourvalue', 'sub_yourvalue']},
			  'add_admin': {'username&&password':
							['none', 'xor_random', 'add_random',
				 'sub_random', 'xor_yourvalue', 'inc',
				 'dec', 'inc_timesyouwant', 'dec_timesyouwant',
				 'add_yourvalue', 'sub_yourvalue']},
			  'disable_firewall': {'':
								   ['none', 'xor_random', 'add_random',
					'sub_random', 'xor_yourvalue', 'inc',
					'dec', 'inc_timesyouwant', 'dec_timesyouwant',
					'add_yourvalue', 'sub_yourvalue']},
		  },
		  'osx_x86':  #generate sub command - os name
		  {
			  'exec': {'file_to_execute': ['none', 'add_random', 'add_yourvalue', 'dec', 'dec_timesyouwant', 'inc', 'inc_timesyouwant', 'sub_random', 'sub_yourvalue', 'xor_random', 'xor_yourvalue']},  #function of shellcode
			  'system':{'command_to_execute': ['none', 'add_random', 'add_yourvalue', 'dec', 'dec_timesyouwant', 'inc_timesyouwant', 'inc','sub_random', 'sub_yourvalue', 'xor_random', 'xor_yourvalue']},  #function of shellcode
			  'chmod': {'file_to_perm&&perm_number':
						['none']},  # function of shellcode
		  },
		  'windows_x86_64': {
			  'exec' :{'file_to_execute':['none']},
		  }
	  },
	  'search': ['search for shellcode in shellstorm', 'keyword_to_search'
				 ],  #shellcode sub command  
	  'download': ['download shellcodes from shellstorm', 'id_to_download'],
	  #add shellcode sub command
	  'shell_storm_list' : ['list all shellcodes in shellstorm','']
	  }],
	'obfuscate':  #obfuscate main command
	[
		'generate obfuscate code',  #description of obfuscate command
		{
			'javascript':  #langauge name
			['simple_hex', 'base64', 'simple_hex_rev', 'simple_base64_rev',
			 'simple_ascii', 'rot13', 'jsfuck'],  #encode types
			'python':
			['simple_hex', 'simple_hex_rev', 'simple_base64_rev', 'simple_ascii', 'rot13'],
			'php':
			['simple_hex', 'base64', 'simple_hex_rev', 'base64_rev', 'simple_ascii', 'rot13'],
			'perl':
			['simple_hex', 'base64', 'simple_hex_rev', 'simple_base64_rev', 
			 'simple_ascii', 'rot13'],
			'ruby':
			['simple_hex', 'base64', 'simple_hex_rev', 'base64_rev', 'simple_ascii', 'rot13'],
		}
	],
	'back': ['Go back one step', ''],
	'clear': ['clears the screen', ''],
	'help': ['show help menu', ''],
	'update': ['check for update', ''],
	'restart': ['restart the software', ''],
	'about': ['about owasp zsc', ''],
	'version': ['software version', ''],
	'exit': ['to exit the software', ''],
	'quit': ['to exit the software', ''],
	'#': ['insert comment', ''],
	#add main command here
}

help = [
	['shellcode', commands['shellcode'][0]],
	['shellcode>generate', 'to generate shellcode'],
	['shellcode>search', commands['shellcode'][1]['search'][0]],
	['shellcode>download', commands['shellcode'][1]['download'][0]],
	['shellcode>shell_storm_list', commands['shellcode'][1]['shell_storm_list'][0]],
	['obfuscate', commands['obfuscate'][0]],
	['back', commands['back'][0]],
	['clear', commands['clear'][0]],
	['help', commands['help'][0]],
	['update', commands['update'][0]],
	['about', commands['about'][0]],
	['restart', commands['restart'][0]],
	['version', commands['version'][0]],
	['exit/quit', commands['exit'][0]],
	['#', commands['#'][0]],
]

help_cli = [
	[['-l','--show-payloads'],'show list of available payloads and required inputs'],
	[['-s','--shell-storm'],'download, search, list shellcode from shell-storm'],
	[['-p','--payload'],'select a payload'],
	[['-i','--input'],'enter the required inputs'],
	[['-c','--assembly-code'],'show assembly code instead of shellcode'],
	[['-o','--output'],'save output [shellcode and assembly code] in a file'],
	[['-u','--update'],commands['update'][0]],
	[['-a','--about'],commands['about'][0]],
	[['-v','--version'],commands['version'][0]],
	[['-e','--samples-cmd'],'show command line samples'],
	[['-h','--help'],commands['help'][0]],
]

cmd_samples = [
	'zsc.py --show-payloads',
	'zsc.py --show-payloads --shell-storm',
	'zsc.py --show-payloads windows_x86',
	'zsc.py -l php',
	'zsc.py --shell-storm search word1',
	'zsc.py -s search "word1 word2"',
	'zsc.py -s download id',
	'zsc.py -s download id -o shellcode.c',
	'zsc.py --payload windows_x86/system/mix_all --input "ls -la"',
	'zsc.py -p linux_x86/chmod/xor_random -i "/etc/passwd~~~777"',
	'zsc.py --payload osx_x86/system/none --input "ls -la" --assembly-code',
	'zsc.py -p linux_x86/write/inc -i "/etc/passwd~~~ali" -c',
	'zsc.py -p linux_x86/system/dec_15 -i "dir" --output shellcode.c',
	'zsc.py -p windows_x86/exec/add_0x4b5ff271 -i "calc.exe" -o shellcode.c',
	'zsc.py -p php/simple_hex -i "/path/file.php"',
]


def about():
	info_ = [['Code', 'https://github.com/Ali-Razmjoo/OWASP-ZSC'], [
		'Contributors',
		'https://github.com/Ali-Razmjoo/OWASP-ZSC/graphs/contributors'
	], ['API', 'http://api.z3r0d4y.com/'], ['Home', 'http://zsc.z3r0d4y.com/'],
			 ['Mailing List', 'https://groups.google.com/d/forum/owasp-zsc'],
			 ['Contact US Now', 'owasp-zsc[at]googlegroups[dot]com']]
	for section in info_:
		info('%s%s%s: %s%s%s\n' %
			 (color.color('red'), section[0], color.color('reset'),
			  color.color('yellow'), section[1], color.color('reset')))


def _help(help):
	write('\n')
	for item in help:
		info('%s%-15s%s\t%s' % (color.color('red'), item[0], color.color('green'),
								item[1]) + '\n')
	info('%s%-10s%s\t%s' % (color.color('red'), 'zsc -h, --help', color.color('green'),
								'basic interface help') + '\n') #add basic interface help
	write('\n')
def _help_cli(help_cli):
	write('\n')
	for item in help_cli:
		items = ''
		for i in item[0]:
			items += str(i) + ', '
		items= items[:-2]
		info('%s%-15s%s\t%s' % (color.color('red'), items, color.color('green'),
			item[1]) + '\n')
	write('\n')

def _show_samples(cmd_samples):
	write('\n')
	for item in cmd_samples:
		info(item+'\n')
	write('\n')

def _show_payloads(commands,check_payload):
	shellcodes = commands['shellcode'][1]['generate']
	obfuscate = commands['obfuscate'][1]
	payloads = []
	for a in shellcodes:
		for b in shellcodes[a]:
			for c in shellcodes[a][b]:
				if check_payload is False:
					y = b + '('
					data = ''
					for z in c.rsplit('&&'):
						data += '\'' + z + '\''+ ','
					y += data[:-1] + ')'
					y = y.replace('(\'\')','()')
					write('\n')
					warn(y+'\n')
				for d in shellcodes[a][b][c]:
					if check_payload is False:
						info(a+'/'+b+'/'+d+'\n')
					if check_payload is True:
						payloads.append(a+'/'+b+'/'+d)
	for a in obfuscate:
		if check_payload is False:
			write('\n')
			warn(a+'\n')
		for b in obfuscate[a]:
			if check_payload is False:
				info(a+'/'+b+'\n')
			if check_payload is True:
				payloads.append(a+'/'+b)
		if check_payload is False:
			write('\n')
	if check_payload is True:
		return payloads

def _clear():
	if 'linux' in sys.platform or 'darwin' in sys.platform:
		os.system('clear')
	elif 'win32' == sys.platform or 'win64' == sys.platform:
		os.system('cls')
	logo()

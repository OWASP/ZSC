#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
from core.alert import *

assembly_code = False #if True: show assembly code instead of shellcode

commands = { #commands section
	'shellcode' : #shellcode main command
		['generate shellcode',
		{ 'generate':  #shellcode sub command - to generate
			{  
				'linux_x86' :  #generate sub command - os name
					{   
						'chmod' : {'file_to_perm&&perm_number':['none','xor_random','xor_yourvalue','add_random','add_yourvalue','sub_random','sub_yourvalue','inc','inc_timesyouwant','dec','dec_timesyouwant','mix_all']}, #function of shellcode
						'dir_create' : {'directory_to_create':['none','xor_random','xor_yourvalue','add_random','add_yourvalue','sub_random','sub_yourvalue','inc','inc_timesyouwant','dec','dec_timesyouwant','mix_all']}, #function of shellcode
						'download' : {'download_url':['none','xor_random','xor_yourvalue','add_random','add_yourvalue','sub_random','sub_yourvalue','inc','inc_timesyouwant','dec','dec_timesyouwant','mix_all']}, #function of shellcode
						'download_execute' : {'download_url&&filename&&command_to_execute':['none','xor_random','xor_yourvalue','add_random','add_yourvalue','sub_random','sub_yourvalue','inc','inc_timesyouwant','dec','dec_timesyouwant','mix_all']}, #function of shellcode
						'exec' : {'file_to_execute':['none','xor_random','xor_yourvalue','add_random','add_yourvalue','sub_random','sub_yourvalue','inc','inc_timesyouwant','dec','dec_timesyouwant','mix_all']}, #function of shellcode
						'file_create' : {'filename&&content':['none','xor_random','xor_yourvalue','add_random','add_yourvalue','sub_random','sub_yourvalue','inc','inc_timesyouwant','dec','dec_timesyouwant','mix_all']}, #function of shellcode
						'script_executor' : {'name_of_script&&name_of_your_script_in_your_pc&&execute_to_command':['none','xor_random','xor_yourvalue','add_random','add_yourvalue','sub_random','sub_yourvalue','inc','inc_timesyouwant','dec','dec_timesyouwant','mix_all']}, #function of shellcode
						'system' : {'command_to_execute':['none','xor_random','xor_yourvalue','add_random','add_yourvalue','sub_random','sub_yourvalue','inc','inc_timesyouwant','dec','dec_timesyouwant','mix_all']}, #function of shellcode
						'write' : {'file_to_write&&content':['none','xor_random','xor_yourvalue','add_random','add_yourvalue','sub_random','sub_yourvalue','inc','inc_timesyouwant','dec','dec_timesyouwant','mix_all']}, #function of shellcode
					},
				#add generate sub command - os name
				},
		  'search':  ['search for shellcode in shellstorm','keyword_to_search'],   #shellcode sub command  
		  'download': ['download shellcodes from shellstorm','id_to_download']
			#add shellcode sub command
		}
		] ,
	'obfuscate' : #obfuscate main command
		[
			'generate obfuscate code', #description of obfuscate command
			{
				'javascript': #langauge name
						['simple_hex'], #encode types
				'python':
						['simple_hex'],
				'php':
						['simple_hex'],
				'perl': 
						['simple_hex'],
			}
		],
	'help' : ['show help menu',''],
	'update' : ['check for update',''],
	'restart': ['restart the software',''],
	'about': ['about owasp zsc',''],
	'version':['software version',''],
	'exit': ['to exit the software',''],
	#add main command here
}


help = [ 
			['shellcode',commands['shellcode'][0]],
			['shellcode>generate','to generate shellcode'],
			['shellcode>search',commands['shellcode'][1]['search'][0]],
			['obfuscate',commands['obfuscate'][0]],
			['help',commands['help'][0]],
			['update',commands['update'][0]],
			['about',commands['about'][0]],
			['restart',commands['restart'][0]],
			['version',commands['version'][0]],
			['exit',commands['exit'][0]],
]
def about():
	info_ = [['Code','https://github.com/Ali-Razmjoo/OWASP-ZSC'],['Contributors','https://github.com/Ali-Razmjoo/OWASP-ZSC/graphs/contributors'],['API','http://api.z3r0d4y.com/'],['Home','http://zsc.z3r0d4y.com/'],['Mailing List','https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project'],['Contact US Now','owasp-zsc-tool-project[at]lists[dot]owasp[dot]org']]
	for section in info_:
		info('%s%s%s: %s%s%s\n'%(color.color('red'),section[0],color.color('reset'),color.color('yellow'),section[1],color.color('reset')))
def _help(help):
	write('\n')
	for h in help:
		info('%s%-10s%s\t%s'%(color.color('red'),h[0],color.color('green'),h[1])+'\n')
	write('\n')
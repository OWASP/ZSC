#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
import sys
from core import update as upd
from core.pyversion import version
version = version() #python version
__version__ = '1.0.9'
__key__ = 'Reboot'
__release_date__ = '2016 January 15'
from core import color
def zcr():
	print (color.color('red') + '''
   ______          __      _____ _____    ___________ _____               
  / __ \ \        / /\    / ____|  __ \  |___  / ____|  __ \              
 | |  | \ \  /\  / /  \  | (___ | |__) |    / / |    | |__) |             
 | |  | |\ \/  \/ / /\ \  \___ \|  ___/    / /| |    |  _  /              
 | |__| | \  /\  / ____ \ ____) | |       / /_| |____| | \ \              
  \____/ _ \/ _\/_/___ \_\_____/|_|  ____/_____\_____|_|__\_\_ _____    _ 
  / ____| |  | |  ____| |    | |    / ____/ __ \|  __ \|  ____|  __ \  | |
 | (___ | |__| | |__  | |    | |   | |   | |  | | |  | | |__  | |__) | | |
  \___ \|  __  |  __| | |    | |   | |   | |  | | |  | |  __| |  _  /  | |
  ____) | |  | | |____| |____| |___| |___| |__| | |__| | |____| | \ \  |_|
 |_____/|_|  |_|______|______|______\_____\____/|_____/|______|_|  \_\ (_)
                                                                          
                                                                          
''' + color.color('cyan') + '\t\t\t'+color.color('green')+'OWASP' + color.color('cyan') + ' ZeroDay Cyber Research Shellcoder\n' + color.color('reset'))
def sig():
	print ('''%s
|----------------------------------------------------------------------------|
|%sVisit%s https://www.%sowasp%s.org/index.php/OWASP_ZSC_Tool_Project ---------------|
|----------------------------------------------------------------------------|%s'''%(color.color('blue'),color.color('red'),color.color('blue'),color.color('red'),color.color('blue'),color.color('reset')))
def start():
	zcr()
	print (color.color('cyan') + 'Please execute with ' + color.color('red') + '-h' + color.color('cyan') + '|' + color.color('red') + '--h' + color.color('cyan') +'|'+color.color('red')+'-help'+color.color('cyan')+'|' + color.color('red') +'--help ' + color.color('cyan') + 'switch to see help menu.' + color.color('reset'))
	sig()
	try:
		if version is 2:
			raw_input('%sPress "%sEnter%s" to continue%s'%(color.color('green'),color.color('red'),color.color('green'),color.color('white')))
		if version is 3:
			input('%sPress "%sEnter%s" to continue%s'%(color.color('green'),color.color('red'),color.color('green'),color.color('white')))
	except:
		sys.exit(color.color('red')+'\n\nKeyboardInterrupt, aborted by user.\n'+color.color('reset')) 
	sys.exit(0)
def menu():
	print ('%sSwitches'%color.color('yellow'))
	print ('%sHelp'%color.color('cyan'))
	print ('%s-h%s, %s--help%s \t to see this help guide'%(color.color('red'),color.color('purple'),color.color('red'),color.color('purple')))
	print ('\n%sShellcode Generating'%color.color('cyan'))
	print ('%s-os%s \t choose your os to create shellcode'%(color.color('red'),color.color('purple')))
	print ('%s-oslist%s	\t list of os for -os switch'%(color.color('red'),color.color('purple')))
	print ('%s-o%s \t output filename'%(color.color('red'),color.color('purple')))
	print ('%s-job%s \t what shellcode gonna do for you ?'%(color.color('red'),color.color('purple')))
	print ('%s-joblist%s \t list of jobs for -job switch'%(color.color('red'),color.color('purple')))
	print ('%s-encode%s \t choose type of encoding/obfuscating'%(color.color('red'),color.color('purple')))
	print ('%s-types%s \t type of encodes for -encode switch'%(color.color('red'),color.color('purple')))
	print ('%s-wizard-shellcode%s \t wizard mode to generate shellcode'%(color.color('red'),color.color('purple')))
	print ('\n%sCode Obfuscating'%color.color('cyan'))
	print ('%s-language%s \t programming language of input file'%(color.color('red'),color.color('purple')))
	print ('%s-lang-list%s \t list of languages for -language switch'%(color.color('red'),color.color('purple')))
	print ('%s-lang-encode%s \t choose type of encoding/obfuscating'%(color.color('red'),color.color('purple')))
	print ('%s-lang-encode-types%s \t type of encodes for -lang-encode switch'%(color.color('red'),color.color('purple')))
	print ('%s-i%s \t input filename [file will re-write]'%(color.color('red'),color.color('purple')))
	print ('\n%sOther Options'%color.color('cyan'))
	print ('%s-update%s \t check for update'%(color.color('red'),color.color('purple')))
	print ('%s-about%s \t about software'%(color.color('red'),color.color('purple')))
	print ('%s-v%s,%s--version%s \t show version'%(color.color('red'),color.color('purple'),color.color('red'),color.color('purple')))
	sys.exit(sig())
def inputcheck():
	print (color.color('yellow')+'''
[+] Wrong input, Check Help Menu ,Execute: zsc ''' + color.color('red') + '-h'+ '\n' + color.color('reset'))
	sys.exit(sig())
os_name_list = ['linux_x86','linux_x64 [Not Available]','linux_arm [Not Available]','linux_mips [Not Available]',
	'freebsd_x86 [Not Available]','freebsd_x64 [Not Available]','windows_x86 [Not Available]','windows_x64 [Not Available]',
	'osx [Not Available]','solaris_x86 [Not Available]','solaris_x64 [Not Available]']
def os_names_list():
	for os in os_name_list:
		if '[Not Available]' in os:
			print ('%s[+]%s '%(color.color('yellow'),color.color('purple')) + os)
		else:
			print ('%s[+]%s '%(color.color('yellow'),color.color('green')) + os)
def os_check(val):
	exist = 0
	for os in os_name_list:
		if str(val) == str(os.rsplit('[Not Available]')[0]):
			exist = 1
	if exist is 1:
		return True
def oslist(val):
	if val is 1:
		os_names_list()
		sys.exit(sig())
	if val is not 1:
		if os_check(val) is True:
			return True
def lang_encode_check(val):
	exist = 0
	for le in lang_encode_list:
		if str(val) == str(le):
			exist = 1
	if exist is 1:
		return True
def lang_encoding_list():
	for le in lang_encode_list:
		if '[Not Available]' in le:
			print ('%s[+]%s '%(color.color('yellow'),color.color('purple')) + le)
		else:
			print ('%s[+]%s '%(color.color('yellow'),color.color('green')) + le)
lang_encode_list = ['simple_hex']
def langencode(val):
		if val is 1:
			lang_encoding_list()
			sys.exit(sig())
		if val is not 1:
				if lang_encode_check(val) is True:
					return True
lang_list = ['bash [Not Available]','go [Not Available]','javascript','perl [Not Available]','php [Not Available]','python [Not Available]','ruby [Not Available]','swift [Not Available]']
def lang_list_name():
	for lang in lang_list:
		if '[Not Available]' in lang:
			print ('%s[+]%s '%(color.color('yellow'),color.color('purple')) + lang)
		else:
			print ('%s[+]%s '%(color.color('yellow'),color.color('green')) + lang)
def lang_check(val):
	exist = 0
	for lang in lang_list:
		if str(val) == str(lang.rsplit('[Not Available]')[0]):
			exist = 1
	if exist is 1:
		return True
def langlist(val):
		if val is 1:
			lang_list_name()
			sys.exit(sig())
		if val is not 1:
			if lang_check(val) is True:
				return True
job_name_list = ['exec(\'/path/file\')','chmod(\'/path/file\',\'permission number\')',
	'write(\'/path/file\',\'text to write\')','file_create(\'/path/file\',\'text to write\')',
	'dir_create(\'/path/folder\')','download(\'url\',\'filename\')',
	'download_execute(\'url\',\'filename\',\'command to execute\')','system(\'command to execute\')',
	'script_executor(\'name of script\',\'path and name of your script in your pc\',\'execute command\')']
def job_list():
	for job in job_name_list:
		print ('%s[+]%s '%(color.color('yellow'),color.color('green')) + job)
def job_check(val):
	exist = 0
	if 'exec(' in val:
		try:
			val = val.replace('exec(\'','')
			val = val.replace('\')','')
			softname = val
			exist = 1
		except:
			exist = 0
	if 'chmod(' in val:
		try: 
			val = val.replace('chmod(\'','')
			val = val.replace('\',\'','\x90\x90\x90')
			val = val.replace('\')','')
			val = val.rsplit('\x90\x90\x90')
			filename = val[0]
			number = val[1]
			int_num = int(number)
			exist = 1
		except:
			exist = 0
	if 'write(' in val: 
		try:
			val = val.replace('write(\'','')
			val = val.replace('\',\'','\x90\x90\x90')
			val = val.replace('\')','')
			val = val.rsplit('\x90\x90\x90')
			filename = val[0]
			content = val[1]
			exist = 1
		except:
			exist = 0
	if 'file_create(' in val:
		try:
			val = val.replace('file_create(\'','')
			val = val.replace('\',\'','\x90\x90\x90')
			val = val.replace('\')','')
			val = val.rsplit('\x90\x90\x90')
			filename = val[0]
			content = val[1]
			exist = 1
		except:
			exist = 0
	if 'dir_create(' in val:
		try:
			val = val.replace('dir_create(\'','')
			val = val.replace('\')','')
			dirname = val
			exist = 1
		except:
			exist = 0
	if 'download(' in val:
		try:
			val = val.replace('download(\'','')
			val = val.replace('\',\'','\x90\x90\x90')
			val = val.replace('\')','')
			val = val.rsplit('\x90\x90\x90')
			url = val[0]
			filename = val[1]
			exist = 1
		except:
			exist = 0
	if 'download_execute(' in val:
		try:
			val = val.replace('download_execute(\'','')
			val = val.replace('\',\'','\x90\x90\x90')
			val = val.replace('\')','')
			val = val.rsplit('\x90\x90\x90')
			url = val[0]
			filename = val[1]
			command = val[2]
			exist = 1
		except:
			exist = 0
	if 'system(' in val:
		try:
			val = val.replace('system(\'','')
			val = val.replace('\')','')
			command = val
			exist = 1
		except:
			exist = 0
	if 'script_executor(' in val:
		try:
			val = val.replace('script_executor(\'','')
			val = val.replace('\',\'','\x90\x90\x90')
			val = val.replace('\')','')
			val = val.rsplit('\x90\x90\x90')
			filename = val[0]
			client_side_name = val[1]
			command = val[2]
			exist = 1
		except:
			exist = 0
	if exist is 1:
		return True

def joblist(val):	
	if val is 1:
		job_list()
		sys.exit(sig())
	if val is not 1:
		if job_check(val) is True:
			return True
encode_name_list = ['none','xor_random','xor_yourvalue','add_random',
	'add_yourvalue','sub_random','sub_yourvalue','inc','inc_timesyouwant',
	'dec','dec_timesyouwant','mix_all']
def encode_name():
	for type in encode_name_list:
		print ('%s[+]%s '%(color.color('yellow'),color.color('green'))+type)
def encode_name_check(val):
	exist = 0
	if val == 'none':
		exist = 1
	if val == 'xor_random':
		exist = 1
	if val == 'add_random':
		exist = 1
	if val == 'sub_random':
		exist = 1
	if val == 'inc':
		exist = 1
	if val == 'dec':
		exist = 1
	if val == 'mix_all':
		exist = 1
	if exist is not 1:
		if 'xor_' in val:
			val = val.replace('xor_','')
			if len(str(val)) is 10:
				exist = 1
		if 'add_' in val:
			val = val.replace('add_','')
			if len(str(val)) is 10:
				exist = 1
		if 'sub_' in val:
			val = val.replace('sub_','')
			if len(str(val)) is 10:
				exist = 1
		if 'inc_' in val:
			val = val.replace('inc_','')
			try:
				val = int(val)
				exist = 1
			except:
				exist = 0
		if 'dec_' in str(val):
			val = val.replace('dec_','')
			try:
				val = int(val)
				exist = 1
			except:
				exist = 0
	if exist is 1:
		return True
def types(val):	
	if val is 1:
		encode_name()
		sys.exit(sig())
	if val is not 1:
		if encode_name_check(val) is True:
			return True
def update():
	upd.startu(__version__)
	sys.exit(sig())
def about():
	zcr()
	info = [['Code','https://github.com/Ali-Razmjoo/OWASP-ZSC'],['Contributors','https://github.com/Ali-Razmjoo/OWASP-ZSC/graphs/contributors'],['API','http://api.z3r0d4y.com/'],['Home','http://zsc.z3r0d4y.com/'],['Mailing List','https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project'],['Contact US Now','owasp-zsc-tool-project[at]lists[dot]owasp[dot]org']]
	for section in info:
		print('%s%s%s: %s%s%s'%(color.color('red'),section[0],color.color('reset'),color.color('yellow'),section[1],color.color('reset')))
	sys.exit(sig())
def soft_version():
	zcr()
	print ('%sOWASP ZSC Version: %s%s'%(color.color('cyan'),color.color('red'),__version__))
	print ('%sKey: %s%s'%(color.color('cyan'),color.color('red'),__key__))
	print ('%sRelease Date: %s%s'%(color.color('cyan'),color.color('red'),__release_date__))
	sys.exit(sig())
#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
import sys
import update as upd
__version__ = '1.0.6'
__key__ = 'B2018'
__release_date__ = '2015 August 10'
__author__ = 'Ali Razmjoo'
from core import color
def zcr():
	print color.color('red') + '''
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
                                                                          
                                                                          
''' + color.color('cyan') + '\t\t\t'+color.color('green')+'OWASP' + color.color('cyan') + ' ZeroDay Cyber Research Shellcoder\n' + color.color('reset')	
def sig():
	print '''%s
|----------------------------------------------------------------------------|
|%sOWASP%s Page: https://www.%sowasp%s.org/index.php/OWASP_ZSC_Tool_Project ---------|
|Author Website: http://%sz3r0d4y%s.com/ ----------------------------------------|
|Project Home: http://%szsc%s.z3r0d4y.com/ --------------------------------------|
|key: %s%s%s | version: %s%s%s | Release Date: %s%s%s --------------------|
|----------------------------------------------------------------------------|'''%(color.color('blue'),color.color('red'),color.color('blue'),color.color('red'),color.color('blue'),color.color('red'),color.color('blue'),color.color('red'),color.color('blue'),color.color('red'),__key__,color.color('blue'),color.color('red'),__version__,color.color('blue'),color.color('red'),__release_date__,color.color('blue'))
def start():
	zcr()
	print color.color('cyan') + 'Please execute with ' + color.color('red') + '-h' + color.color('cyan') + '|' + color.color('red') + '--h' + color.color('cyan') +'|'+color.color('red')+'-help'+color.color('cyan')+'|' + color.color('red') +'--help ' + color.color('cyan') + 'switch to see help menu.' + color.color('reset')
	sig()
	try:
		raw_input('%sPress "%sEnter%s" to continue%s'%(color.color('green'),color.color('red'),color.color('green'),color.color('white')))
	except:
		print '\n\nKeyboardInterrupt, aborted by user.\n'
	sys.exit(0)
def menu():
	print '''
%sSwitches%s:
%s-h%s, %s--h%s, %s-help%s, %s--help%s => to see this help guide  
%s-os%s => choose your os to create shellcode
%s-oslist%s	=> list os for switch -os
%s-o%s => output filename
%s-job%s => what shellcode gonna do for you ?
%s-joblist%s => list of -job switch
%s-encode%s => generate shellcode with encode
%s-types%s => types of encode for -encode switch
%s-wizard%s => wizard mod

%s-update%s => check for update
%s-about%s => about software and %sdevelopers%s.'''%(color.color('yellow'),color.color('purple'),color.color('red'),color.color('purple'),color.color('red'),color.color('purple'),color.color('red'),color.color('purple'),color.color('red'),color.color('purple'),color.color('red'),color.color('purple'),color.color('red'),color.color('purple'),color.color('red'),color.color('purple'),color.color('red'),color.color('purple'),color.color('red'),color.color('purple'),color.color('red'),color.color('purple'),color.color('red'),color.color('purple'),color.color('red'),color.color('purple'),color.color('red'),color.color('purple'),color.color('red'),color.color('purple'),color.color('red'),color.color('purple'))
	
	sys.exit(sig())
def inputcheck():
	print color.color('yellow')+'''
[+] Wrong input, Check Help Menu ,Execute: zsc ''' + color.color('red') + '-h'+ '\n' + color.color('reset')
	sys.exit(sig())
os_name_list = ['linux_x86','linux_x64','linux_arm','linux_mips',
	'freebsd_x86','freebsd_x64','windows_x86','windows_x64',
	'osx','solaris_x86','solaris_x64']
def os_names_list():
	for os in os_name_list:
		print '%s[+]%s'%(color.color('yellow'),color.color('green')),os
def os_check(val):
	exist = 0
	for os in os_name_list:
		if str(val) == str(os):
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

job_name_list = ['exec(\'/path/file\')','chmod(\'/path/file\',\'permission number\')',
	'write(\'/path/file\',\'text to write\')','file_create(\'/path/file\',\'text to write\')',
	'dir_create(\'/path/folder\')','download(\'url\',\'filename\')',
	'download_execute(\'url\',\'filename\',\'command to execute\')','system(\'command to execute\')',
	'script_executor(\'name of script\',\'path and name of your script in your pc\',\'execute command\')']
def job_list():
	for job in job_name_list:
		print '%s[+]%s'%(color.color('yellow'),color.color('green')),job
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
		print '%s[+]%s'%(color.color('yellow'),color.color('green')),type
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
	zcr(),'\n'
	developers = ['Ali Razmjoo | OWASP:Ali Razmjoo | Twitter: @Ali_Razmjo0 | z3r0d4y.com',]
	print color.color('red') + 'Project Coordinator: ' + color.color('cyan') + 'Ali Razmjoo\n\n' + color.color('yellow') + 'Developers:'
	sys.stdout.write(color.color('cyan'))
	for developer in developers:
		print developer
	sys.exit(sig())

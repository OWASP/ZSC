#!/usr/bin/env python
import start
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
import sys
from lib import analyser
from core import start
from core import color
def exist():
	check_num = False
	if len(sys.argv) > 1:
		check_num = True
	return check_num
def check():
	checkargv = False
	if len(sys.argv) is 2:
		if str(sys.argv[1]) == '-oslist':
			checkargv = True
			start.oslist(1)
		if str(sys.argv[1]) == '-joblist':
			checkargv = True
			start.joblist(1)
		if str(sys.argv[1]) == '-types':
			checkargv = True
			start.types(1)
		if str(sys.argv[1]) == '-h':
			checkargv = True
			start.menu()
		if str(sys.argv[1]) == '--h':
			checkargv = True
			start.menu()
		if str(sys.argv[1]) == '-help':
			checkargv = True
			start.menu()
		if str(sys.argv[1]) == '--help':
			checkargv = True
			start.menu()
		if str(sys.argv[1]) == '-update':
			checkargv = True
			start.update()
		if str(sys.argv[1]) == '-about':
			checkargv = True
			start.about()
		if str(sys.argv[1]) == '-wizard':
			checkargv = True
			start.zcr()
			try:
				t = True
				print '\n'+color.color('yellow')+'Default OS Name is linux_x86, Enter OS Name or Enter "list" to see OS List'
				while t:
					osname = raw_input(color.color('cyan')+'OS Name: '+color.color('white')).replace('\n','')
					if osname == '':
						osname = 'linux_x86'
					check = start.oslist(osname)
					if osname == 'list':
						start.os_names_list()
						check = 1
					if check is True:
						print color.color('blue')+'OS Name set to "%s%s%s"'%(color.color('red'),osname,color.color('blue'))
						t = False
					if check is not True and check is not 1:
						print color.color('red')+'Wrong Input'	
				t = True
				print '\n'+color.color('yellow')+'Default Job is exec(\'/bin/bash\'), Enter Job Type or Enter "list" to see Jobs List'
				while t:
					job = raw_input(color.color('cyan')+'Job:'+color.color('white')).replace('\n','')
					if job == '':
						job = 'exec(\'/bin/bash\')'
					check = start.job_check(job)
					if job == 'list':
						start.job_list()
						check = 1
					if check is True:
						print color.color('blue')+'Job set to "%s%s%s"'%(color.color('red'),job,color.color('blue'))
						t = False
					if check is not True and check is not 1:
						print color.color('red')+'Wrong Input'
				t = True
				print '\n'+color.color('yellow')+'Default Encode Type is none, Enter Encode Type or Enter "list" to see Encodes List'
				while t:
					encode = raw_input(color.color('cyan')+'Encode:'+color.color('white')).replace('\n','')
					if encode == '':
						encode = 'none'
					check = start.encode_name_check(encode)
					if encode == 'list':
						start.encode_name()
						check = 1
					if check is True:
						print color.color('blue')+'Encode Type set to "%s%s%s"'%(color.color('red'),encode,color.color('blue'))
						t = False
					if check is not True and check is not 1:
						print color.color('red')+'Wrong Input'
				t = True
				print '\n'+color.color('yellow')+'Default Filename is shellcode.c, Enter Filename or Just Enter to skip'
				while t:
					filename = raw_input(color.color('cyan')+'Filename: '+color.color('white')).replace('\n','')
					if filename == '':
						filename = 'shellcode.c'
					check = False
					try:
						file = open(filename,'w')
						file.write('')
						file.close()
						check = True
					except:
						check = False
					if check is True:
						print color.color('blue')+'Filename set to "%s%s%s"'%(color.color('red'),filename,color.color('blue'))
						t = False
					if check is False:
						print color.color('red')+'File is not writable, Try other name or change directory'
			except (KeyboardInterrupt, SystemExit):
				print '\n\nAborted by user.\n'
				sys.exit(0)
			checkargv = True
			if start.oslist(osname) is not True:
				checkargv = False
			if start.types(encode) is not True:
				checkargv = False
			if start.joblist(job) is not True:
				checkargv = False
			if checkargv is False:
				start.inputcheck()
			content = osname + '\x90\x90\x90' + filename + '\x90\x90\x90' + encode + '\x90\x90\x90' + job
			analyser.do(content)
			sys.exit(start.sig())
		if checkargv is False:
			start.inputcheck()
		return checkargv
	if len(sys.argv) > 2:
		checkargv = True
		for argv_check in sys.argv:
			if argv_check == '-h':
				checkargv = False
			if argv_check == '--h':
				checkargv = False
			if argv_check == '-help':
				checkargv = False
			if argv_check == '--help':
				checkargv = False
			if argv_check == '-types':
				checkargv = False
			if argv_check == '-oslist':
				checkargv = False
			if argv_check == '-joblist':
				checkargv = False
			if argv_check == '-update':
				checkargv = False
			if argv_check == '-wizard':
				checkargv = False
		if checkargv is False:
			start.inputcheck()
		checkargv = False
		counter = 0
		total_counter = 0
		os_counter = 0
		filename_counter = 0
		job_counter = 0
		encode_counter = 0
		for argv_check in sys.argv:
			if argv_check == '-os':
				counter += 1
				os_counter = total_counter + 1
			if argv_check == '-o':
				counter += 1
				filename_counter = total_counter + 1
			if argv_check == '-job':
				counter += 1
				job_counter = total_counter + 1
			if argv_check == '-encode':
				counter += 1
				encode_counter = total_counter + 1
			total_counter += 1
		if counter is 4:
			checkargv = True
		if checkargv is False:
			start.inputcheck()
		checkargv = False
		if start.oslist(sys.argv[os_counter]) is not True:
			return checkargv
		if start.types(sys.argv[encode_counter]) is not True:
			return checkargv
		if start.joblist(sys.argv[job_counter]) is not True:
			return checkargv
		checkargv = True
		return checkargv
def run():
	counter = 0
	total_counter = 0
	os_counter = 0
	filename_counter = 0
	job_counter = 0
	encode_counter = 0
	for argv_check in sys.argv:
		if argv_check == '-os':
			counter += 1
			os_counter = total_counter + 1
		if argv_check == '-o':
			counter += 1
			filename_counter = total_counter + 1
		if argv_check == '-job':
			counter += 1
			job_counter = total_counter + 1
		if argv_check == '-encode':
			counter += 1
			encode_counter = total_counter + 1
		total_counter += 1
	if counter is 4:
		checkargv = True
	if checkargv is False:
		start.inputcheck()
	checkargv = False
	if start.oslist(sys.argv[os_counter]) is not True:
		return checkargv
	if start.types(sys.argv[encode_counter]) is not True:
		return checkargv
	if start.joblist(sys.argv[job_counter]) is not True:
		return checkargv
	try:
		writer = open(sys.argv[filename_counter],'w')
		writer.write('')
		writer.close()
	except:
		print color.color('red')+'File is not writable, Try other name or change directory'+color.color('reset')
		sys.exit(start.sig())
	os = sys.argv[os_counter]
	filename = sys.argv[filename_counter]
	encode = sys.argv[encode_counter]
	job = sys.argv[job_counter]
	content = os + '\x90\x90\x90' + filename + '\x90\x90\x90' + encode + '\x90\x90\x90' + job
	return content

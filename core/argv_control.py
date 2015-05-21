#!/usr/bin/env python
import start
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
import sys
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
	writer = open('output/'+sys.argv[filename_counter],'w')
	writer.write('')
	writer.close()
	os = sys.argv[os_counter]
	filename = sys.argv[filename_counter]
	encode = sys.argv[encode_counter]
	job = sys.argv[job_counter]
	content = os + '\x90\x90\x90' + filename + '\x90\x90\x90' + encode + '\x90\x90\x90' + job
	return content

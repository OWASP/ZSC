#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
from core.compatible import *
from core.alert import *
from core import color
if version() is 2:
	from urllib import urlopen
if version() is 3:
	from urllib.request import urlopen
def _search_shellcode():
	url = 'http://shell-storm.org/api/?s='
	try:
		if version() is 3:
			keyword = input('%skeyword_to_search>%s '%(color.color('blue'),color.color('yellow')))
		if version() is 2:
			keyword = raw_input('%skeyword_to_search>%s '%(color.color('blue'),color.color('yellow')))
	except:
		return
	keyword=keyword.replace(' ','*')
	try:
		data = urlopen(url+keyword).read()
	except:
		warn('connection error')
		return
	for shellcode_ in data.rsplit('\n'):
		try:
			shellcode_ = shellcode_.rsplit('::::')
			info('author: %s\tshellcode_id: %s\tplathform: %s\ttitle: %s\n'%(shellcode_[0],shellcode_[3],shellcode_[1],shellcode_[2]))
		except:
			pass
	write('\n')
def _download_shellcode():
	try:
		if version() is 3:
			id = input('%sshellcode_id>%s '%(color.color('blue'),color.color('yellow')))
		if version() is 2:
			id = raw_input('%sshellcode_id>%s '%(color.color('blue'),color.color('yellow')))
	except:
		return
	url = 'http://shell-storm.org/shellcode/files/shellcode-%s.php'%(str(id))
	try:
		data = urlopen(url).read().rsplit('<pre>')[1].rsplit('<body>')[0]
	except:
		warn('connection error')
		return
	write(data)
	
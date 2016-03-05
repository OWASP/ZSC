#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
from core.compatible import *
from core.alert import *
from core import color
from core.get_input import _input
from core.file_out import downloaded_file_output
if version() is 2:
	from urllib import urlopen
if version() is 3:
	from urllib.request import urlopen
def _search_shellcode():
	url = 'http://shell-storm.org/api/?s='
	keyword = _input('%skeyword_to_search%s'%(color.color('blue'),color.color('yellow')),'any',True)
	keyword=keyword.replace(' ','*')
	try:
		data = urlopen(url+keyword).read()
		if version() is 3:
			data = data.decode('utf-8')
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
	id = _input('%sshellcode_id%s'%(color.color('blue'),color.color('yellow')),'int',True)
	url = 'http://shell-storm.org/shellcode/files/shellcode-%s.php'%(str(id))
	try:
		if version() is 2:
			data = urlopen(url).read().rsplit('<pre>')[1].rsplit('<body>')[0]
		if version() is 3:
			data = urlopen(url).read().decode('utf-8').rsplit('<pre>')[1].rsplit('<body>')[0]
	except:
		warn('connection error\n')
		return
	write(data+'\n\n')	
	file_or_not=_input('Shellcode output to a .c file?(y or n)', 'any', True)
	if file_or_not[0]=='y':
		target=_input('Target .c file?', 'any', True)
		downloaded_file_output(target, data)
				

					
	
	

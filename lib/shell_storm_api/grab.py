#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
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
	from HTMLParser import HTMLParser
if version() is 3:
	from urllib.request import urlopen
	import html

def _html_decode(data):
	"""HTML Decode function separate to handle py2 and py3."""
	if version() is 2:
		h = HTMLParser()
		return h.unescape(data)
	if version() is 3:
		return html.unescape(data)

def _search_shellcode(cli,keyword):
	url = 'http://shell-storm.org/api/?s='
	if cli is True:
		pass
	else:
		keyword = _input('%skeyword_to_search%s' %
					 (color.color('blue'), color.color('yellow')), 'any', True)
	keyword = keyword.replace(' ', '*')
	try:
		data = urlopen(url + keyword).read()
		if version() is 3:
			data = data.decode('utf-8')
	except:
		warn('connection error')
		return
	for shellcode_ in data.rsplit('\n'):
		try:
			shellcode_ = shellcode_.rsplit('::::')
			info('author: %s\tshellcode_id: %s\tplatform: %s\ttitle: %s\n' %
				 (shellcode_[0], shellcode_[3], shellcode_[1], shellcode_[2]))
		except:
			pass
	write('\n')


def _download_shellcode(cli,id,name):
	if cli is True:
		pass
	else:
		id = _input('%sshellcode_id%s' %
				(color.color('blue'), color.color('yellow')), 'int', True)
	url = 'http://shell-storm.org/shellcode/files/shellcode-%s.php' % (str(id))
	try:
		if version() is 2:
			data = urlopen(url).read().rsplit('<pre>')[1].rsplit('<body>')[0]
		if version() is 3:
			data = urlopen(url).read().decode('utf-8').rsplit('<pre>')[
				1].rsplit('<body>')[0]
	except:
		warn('connection error\n')
		return

	write(_html_decode(data) + '\n\n')

	if cli is False:
		file_or_not = _input('Shellcode output to a .c file?(y or n)', 'any', True)
		if file_or_not[0] == 'y':
			target = _input('Target .c file?', 'any', True)
			downloaded_file_output(target, _html_decode(data))
	else:
		if name != '':
			downloaded_file_output(name, _html_decode(data))
			
def _grab_all():
	url = 'http://shell-storm.org/shellcode/'
	try:
		if version() is 2:
			data = urlopen(url).read().rsplit('\n')
		if version() is 3:
			data = urlopen(url).read().decode('utf-8').rsplit('\n')
	except:
		warn('connection error\n')
		return
	for shellcode in data:
		if '/shellcode/files/shellcode-' in shellcode:
			id = shellcode.rsplit('<li><a href="/shellcode/files/shellcode-')[1].rsplit('.php')[0]
			title = shellcode.rsplit('">')[1].rsplit('</a>')[0]
			author = shellcode.rsplit('<i>')[1].rsplit('</i>')[0]
			info('id: ' + id + ' - ' + title + ' ' + author + '\n')

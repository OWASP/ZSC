#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
import random
import binascii
import string
from core.compatible import version
_version = version()
chars = string.digits + string.ascii_letters


def start(type, shellcode, job):
    value = str(type.rsplit('xor_')[1][2:])
    for line in shellcode.rsplit('\n'):
        if 'push' in line and '$0x' in line and ',' not in line and len(
                line) > 14:
            data = line.rsplit('push')[1].rsplit('$0x')[1]
            t = True
            while t:
                ebx_1 = value
                ebx_2 = "%x" % (int(data, 16) ^ int(ebx_1, 16))
                if str('00') not in str(ebx_1) and str('00') not in str(
                        ebx_2) and len(ebx_2.replace('-', '')) >= 7 and len(
                            ebx_1) >= 7 and '-' not in ebx_1:
                    ebx_2 = ebx_2.replace('-', '')
                    if job == 'exec':
                        command = '\npush %%ebx\npush $0x%s\npop %%ebx\npush $0x%s\npop %%ecx\nxor %%ebx,%%ecx\npop %%ebx\npush %%ecx\n' % (
                            str(ebx_1), str(ebx_2))
                    elif job == 'add_admin' or job == 'dir_create' or job == 'download_exec':
                        command = '\npush %%ebx\npush $0x%s\npop %%ebx\npush $0x%s\npop %%ecx\nxor %%ebx,%%ecx\npop %%ebx\npush %%ecx\n' % (
                            str(ebx_1), str(ebx_2))
                    elif job == 'create_file' or job == 'disable_firewall' or job == 'download_tofile':
                        command = '\npush %%eax\npush $0x%s\npop %%eax\npush $0x%s\npop %%ecx\nxor %%eax,%%ecx\npop %%eax\npush %%ecx\n' % (
                            str(ebx_1), str(ebx_2))
                    shellcode = shellcode.replace(line, command)
                    t = False
    return shellcode

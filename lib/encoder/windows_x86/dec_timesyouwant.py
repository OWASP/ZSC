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


def start(decvalue, shellcode, job):
    times = int(decvalue.rsplit('dec_')[1])
    for line in shellcode.rsplit('\n'):
        if 'push' in line and '$0x' in line and ',' not in line and len(
                line) > 14:
            data = line.rsplit('push')[1].rsplit('$0x')[1]
            ecx_2 = "%x" % (int(data, 16) + times)
	    dec = 'dec %ecx\n' * times
            command = '\npush $0x%s\npop %%ecx\n%s\npush %%ecx\n' % (str(ecx_2), dec)
            shellcode = shellcode.replace(line, command)
    return shellcode

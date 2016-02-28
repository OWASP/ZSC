#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
import binascii
import random
import string
import re
import base64
from core.compatible import version
_version = version()

def encode(f):
    base64_arr = ''
    val_name = ''.join(random.choice(string.ascii_lowercase+string.ascii_uppercase) for i in range(50))
    data = ''
    eval = ''
    n = 0
    m = 0
    
    data = val_name + ' = "' + str(binascii.b2a_base64(f)) +'"'
    eval = 'str('+ val_name + ')+'
    var_b64 = ''.join(random.choice(string.ascii_lowercase+string.ascii_uppercase) for i in range(50))    
    var_data = ''.join(random.choice(string.ascii_lowercase+string.ascii_uppercase) for i in range(50))
    func_name = ''.join(random.choice(string.ascii_lowercase+string.ascii_uppercase) for i in range(50))
    func_argv = ''.join(random.choice(string.ascii_lowercase+string.ascii_uppercase) for i in range(50))
    f = '''
import binascii
import sys
%s
def %s(%s):
    if sys.version_info.major is 2:
        return str(binascii.a2b_base64(%s))
    elif sys.version_info.major is 3:
        return str(binascii.a2b_base64(%s))
    else:
        sys.exit('Your python version is not supported!')
%s = %s
exec(%s(%s))
'''%(data,func_name,func_argv,func_argv,func_argv,var_data,eval[:-1],func_name,var_data)
    return f

def start(content):
    return str(str('\'\'\'\n')+str(content.replace('\'\'\'','\\\'\\\'\\\''))+str('\n\'\'\'') + str(encode(content))+str('\n'))
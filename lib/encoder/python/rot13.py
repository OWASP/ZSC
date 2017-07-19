#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
import binascii
import random
import string
import codecs
from core.compatible import version
_version = version()


def encode(f):
    var_name = ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    if _version is 2:
        rev_data = f.encode("rot13")
        data = var_name + ' = """' + str(rev_data) + '"""'
    if _version is 3:
        rev_data = codecs.encode(f, "rot-13")
        data = var_name + ' = """' + str(rev_data) + '"""'

    func_name = ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    func_argv = ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    f = '''
import binascii
import sys
import codecs
%s
def %s(%s):
    if sys.version_info.major is 2:        
        return str(%s.decode("rot13"))
    elif sys.version_info.major is 3:
        return str(codecs.decode(%s, "rot-13"))
    else:
        sys.exit('Your python version is not supported!')
exec(%s(%s))
''' % (data, func_name, func_argv, func_argv, func_argv,
       func_name, var_name)
    return f


def start(content,cli):
    return str(str('\'\'\'\n') + str(content.replace('\'\'\'', '\\\'\\\'\\\''))
               + str('\n\'\'\'') + str(encode(content)) + str('\n'))

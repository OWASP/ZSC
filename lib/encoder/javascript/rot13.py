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
    base64_arr = ''
    val_name = ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    data = ''
    if _version is 2:
        data = val_name + '= ` ' + str(f.encode("rot13")) + '`;'
    if _version is 3:
        data = val_name + '= `' + str(codecs.encode(f, "rot-13")) + '`;'
    var_b64 = ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    var_str = ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    var_data = ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    func_name = ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    func_argv = ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    f = '''
%s
function rot(s) {
    return s.replace(/[a-zA-Z]/g, function (c) {
        return String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26);
    });
}
function %s(%s) {
    return rot(%s);


}
eval(%s(%s));''' % (data, func_name, func_argv, func_argv, func_name, val_name)
    return f


def start(content,cli):
    return str(str('/*\n') + str(content.replace('*/', '*_/')) + str('\n*/') +
               str(encode(content)) + str('\n'))

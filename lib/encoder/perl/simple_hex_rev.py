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
from core.compatible import version
_version = version()


def encode(f):
    var_name = '$' + ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    data = ''
    if _version is 2:
        rev_data = binascii.b2a_hex(f)[::-1]
        data = var_name + ' = "' + rev_data + '";\n'

    if _version is 3:
        rev_data = binascii.b2a_hex(f.encode('utf8')).decode('utf8')[::-1]
        data = var_name + ' = "' + rev_data + '";\n'

    var_str = '$' + ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    var_counter = '$' + ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    var_data = '$' + ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    var_rev = '$' + ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    func_name = ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    func_argv = '$' + ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    f = '''
%s
sub %s {
    %s = shift;
    %s = reverse %s;
    for(%s = 0; %s < length %s; %s += 2) {
        %s .= chr(hex(substr(%s,%s,2)));
    }
    return %s;
}
%s = %s;
eval %s(%s);
''' % (data, func_name, func_argv, var_rev, func_argv, var_counter,
       var_counter, var_rev, var_counter, var_str, var_rev, var_counter,
       var_str, var_data, var_name, func_name, var_data)
    return f


def start(content,cli):
    return str(str('=begin\n') + str(content.replace(
        '=begin', '#=begin').replace('=cut', '#=cut')) + str('\n=cut') + str(
            encode(content)) + str('\n'))

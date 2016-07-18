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
    hex_arr = []
    val_names = []
    data = ''
    eval = ''
    n = 0
    m = 0
    for line in f:
        if _version is 2:
            hex_arr.append(str(binascii.b2a_hex(line)))
        if _version is 3:
            hex_arr.append(str((binascii.b2a_hex(str(line).encode('latin-1'))
                                ).decode('latin-1')))
    length = len(hex_arr)
    while (length != 0):
        val_names.append(''.join(random.choice(string.ascii_lowercase +
                                               string.ascii_uppercase)
                                 for i in range(50)))
        length -= 1
    for hex in hex_arr:
        data += '$' + val_names[n] + ' = "' + str(hex) + '";\n'
        n += 1
    while (m <= n - 1):
        eval += '$' + val_names[m] + '.'
        m += 1
    var_str = '$' + ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    var_counter = '$' + ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    var_data = '$' + ''.join(
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
    for(%s = 0; %s < length %s; %s += 2) {
        %s .= chr(hex(substr(%s,%s,2)));
    }
    return %s;
}
%s = %s;
eval %s(%s);
''' % (data, func_name, func_argv, var_counter, var_counter, func_argv,
       var_counter, var_str, func_argv, var_counter, var_str, var_data,
       eval[:-1], func_name, var_data)
    return f


def start(content,cli):
    return str(str('=begin\n') + str(content.replace(
        '=begin', '#=begin').replace('=cut', '#=cut')) + str('\n=cut') + str(
            encode(content)) + str('\n'))

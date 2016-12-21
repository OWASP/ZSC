#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
import sys
from core import color


def info(content):
    num_newline = len(content) - len(content.rstrip("\n"))
    sys.stdout.write(color.color('yellow') + '[+] ' + color.color('green') +
                     content[:-num_newline] + color.color('reset') + "\n"*num_newline)
    return


def write(content):
    sys.stdout.write(content)
    return


def warn(content):
    num_newline = len(content) - len(content.rstrip("\n"))
    sys.stdout.write(color.color('red') + '[!] ' + color.color('yellow') +
                     content[:-num_newline] + color.color('reset') + "\n"*num_newline)
    return


def error(content):
    sys.stdout.write(content)
    return

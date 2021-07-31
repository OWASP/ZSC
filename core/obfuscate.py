#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
from core.alert import *
from core.compatible import version
import os


def obf_code(lang, encode, filename, content,cli):
    if version() is 3:
        content = content.decode('utf-8')
    start = getattr(
        __import__('lib.encoder.%s.%s' % (lang, encode),
                   fromlist=['start']),
        'start')  #import endoing module
    content = start(content,cli)  #encoded content as returned value
    if version() is 3:
        content = bytes(content, 'utf-8')
    f = open(filename, 'wb')  #writing content
    f.write(content)
    f.close()

    ext = ''           # changing the file extension to desired extension
    if lang == 'python':
        ext = '.py'
    if lang == 'javascript':
        ext = '.js'
    if lang == 'perl':
        ext = '.pl'
    if lang == 'ruby':
        ext = '.rb'
    if lang == 'php':
        ext = '.php'

    if '.' in filename:
        filename_list = filename.split('.')
        filename_list.pop()  # now filename 2 has only file name without extension
        # pop is used because filename can be some.random.name.txt and program should still work
    else:
        filename_list = [filename]   # this means file has no extension

    filename_list.append(ext)  # now filename 2 is an array with filename and correct extension.
    filename_with_ext = ''
    filename_with_ext = filename_with_ext.join(filename_list)

    os.rename(filename, filename_with_ext)  # renaming
    info('file "%s" encoded successfully!\n' % filename_with_ext)
    return

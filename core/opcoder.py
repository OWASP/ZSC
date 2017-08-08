#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''


def op(shellcode, os):
    if os == 'linux_x86':  #for linux_x86 os
        from lib.opcoder.linux_x86 import convert
        return convert(shellcode)
    if os == 'windows_x86':  #for windows os
        from lib.opcoder.windows_x86 import convert
        return convert(shellcode)
    if os == 'osx_x86':  # for osx_x86 os
        from lib.opcoder.osx_x86 import convert
        return convert(shellcode)
    if os == 'windows_x86_64':
        from lib.opcoder.windows_x86_64 import convert
    #add os opcoder here
    return shellcode

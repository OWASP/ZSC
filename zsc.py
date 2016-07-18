#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
import sys
import os
from core.compatible import *
from core.start import logo
from core.controller import _interface

def main():
    ''' Main Fucntion '''
    logo()  #zsc logo
    _interface()


if __name__ == "__main__":
    check()  #check os and python version if compatible
    main()  #execute main function

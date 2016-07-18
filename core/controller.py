#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
from core import run
from core.cli import _cli_start
import sys
import os

exec (compile(
    open(
        str(os.path.dirname(os.path.abspath(__file__)).replace('\\', '/')) +
        '/commands.py', "rb").read(), str(os.path.dirname(os.path.abspath(
            __file__)).replace('\\', '/')) + '/commands.py', 'exec'))

			
def _interface():
	if len(sys.argv) is 1:
		run.engine(commands)  #run engine with user friendly interface
	else:
		_cli_start(commands)  #run engine with basic interface
		
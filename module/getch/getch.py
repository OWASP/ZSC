#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
"""
py-getch https://github.com/joeyespo/py-getch
--------

Portable getch() for Python.

:copyright: (c) 2013-2015 by Joe Esposito.
:license: MIT, see LICENSE for more details.
"""
try:
	from msvcrt import getch
except ImportError:
	def getch():
		"""
		Gets a single character from STDIO.
		"""
		import sys
		import tty
		import termios
		fd = sys.stdin.fileno()
		old = termios.tcgetattr(fd)
		try:
			tty.setraw(fd)
			return sys.stdin.read(1)
		finally:
			termios.tcsetattr(fd, termios.TCSADRAIN, old)
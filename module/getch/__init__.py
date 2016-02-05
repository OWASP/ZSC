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

__version__ = '1.0.1'

from .getch import getch

__all__ = ['__version__', 'getch']

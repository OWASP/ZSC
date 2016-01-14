#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
import binascii
from core import stack
from core import template
def run(path_file,content):
	null = len(path_file) % 4
	if null is not 0:
		null = ''
	if null is 0:
		null = 'xor %ebx,%ebx\npush %ebx\n'
	return template.write(str(null),stack.generate(str(path_file),'%ebx','string'),stack.generate(str(content),'%ecx','string'),stack.generate(str(len(content)),'%edx','int'))

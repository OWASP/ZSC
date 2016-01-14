#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
from core import stack
from core import template
def run(file_to_perm,perm_num):
	return template.chmod(stack.generate(perm_num,'%ecx','int'),stack.generate(file_to_perm,'%ebx','string'))

	

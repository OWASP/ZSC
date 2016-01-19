#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
def op(shellcode,os):
	if os == 'linux_x86': #for linux_x86 os
		from lib.opcoder.linux_x86 import convert
		return convert(shellcode)
	#add os opcoder here
	return shellcode
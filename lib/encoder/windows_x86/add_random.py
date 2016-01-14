#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
def start(shellcode,job):
	if 'chmod(' in job:	
		shellcode = 'N' + shellcode
	if 'dir_create(' in job:
		shellcode = 'N' + shellcode
	if 'download_execute(' in job:
		shellcode = 'N' + shellcode
	if 'download(' in job:
		shellcode = 'N' + shellcode
	if 'exec(' in job:
		shellcode = 'N' + shellcode
	if 'file_create(' in job:
		shellcode = 'N' + shellcode
	if 'script_executor(' in job:
		shellcode = 'N' + shellcode
	if 'system(' in job:
		shellcode = 'N' + shellcode
	if 'write(' in job:
		shellcode = 'N' + shellcode
	return shellcode

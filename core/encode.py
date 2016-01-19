#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
def encode_process(encode,shellcode,os,func):
	if encode == 'none':
		return shellcode
	elif 'linux_x86' in os:	
		if encode == 'add_random':
			from lib.encoder.linux_x86.add_random import start
			return start(shellcode,func)	
		elif 'add_' in encode:
			from lib.encoder.linux_x86.add_yourvalue import start
			return start(encode,shellcode,func)
		elif encode == 'dec':
			from lib.encoder.linux_x86.dec import start
			return start(shellcode,func)	
		elif 'dec_' in encode:
			from lib.encoder.linux_x86.dec_timesyouwant import start
			return start(encode,shellcode,func)
		elif encode == 'inc':
			from lib.encoder.linux_x86.inc import start
			return start(shellcode,func)	
		elif 'inc_' in encode:
			from lib.encoder.linux_x86.inc_timesyouwant import start
			return start(encode,shellcode,func)
		elif encode == 'mix_all':
			from lib.encoder.linux_x86.mix_all import start
			return start(shellcode,func)	
		elif encode == 'sub_random':
			from lib.encoder.linux_x86.sub_random import start
			return start(shellcode,func)	
		elif 'sub_' in encode:
			from lib.encoder.linux_x86.sub_yourvalue import start
			return start(encode,shellcode,func)
		elif encode == 'xor_random':
			from lib.encoder.linux_x86.xor_random import start
			return start(shellcode,func)
		elif 'xor_' in encode:
			from lib.encoder.linux_x86.xor_yourvalue import start
			return start(encode,shellcode,func)
	return shellcode
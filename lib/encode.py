#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''

def process(type,shellcode):
	if type == 'none':
		from encoder.none import start
		return start(shellcode)		
	if type == 'add_random':
		from encoder.add_random import start
		return start(shellcode)	
	if 'add_' in type:
		from encoder.add_yourvalue import start
		shellcode = start(type,shellcode)
		return shellcode
	if type == 'dec':
		from encoder.dec import start
		return start(shellcode)	
	if 'dec_' in type:
		from encoder.dec_timesyouwant import start
		shellcode = start(type,shellcode)
		return shellcode	
	if type == 'inc':
		from encoder.inc import start
		return start(shellcode)	
	if 'inc_' in type:
		from encoder.inc_timesyouwant import start
		shellcode = start(type,shellcode)
		return shellcode	
	if type == 'mix_all':
		from encoder.mix_all import start
		return start(shellcode)	
	if type == 'sub_random':
		from encoder.sub_random import start
		return start(shellcode)	
	if 'sub_' in type:
		from encoder.sub_yourvalue import start
		shellcode = start(type,shellcode)
		return shellcode
	if type == 'xor_random':
		from encoder.xor_random import start
		return start(shellcode)
	if 'xor_' in type:
		from encoder.xor_yourvalue import start
		shellcode = start(type,shellcode)
		return shellcode	
		

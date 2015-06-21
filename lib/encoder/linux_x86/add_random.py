#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
def start(shellcode,job):
	print 'This encoding method will available in next versions.' 
	return shellcode
''' Building for next version ...
import random,binascii,string
chars = string.ascii_letters + string.digits
def start(type,shellcode):
	spliting = shellcode.rsplit('\n')
	values = ''
	for line in spliting:
		if '$0x' in line and len(line.rsplit()[1]) is 11:
			values += line.rsplit()[1].replace('$0x','') + '_z3r0_'
	values = values.rsplit('_z3r0_')[:-1]
	values_xor = ''
	for s1 in values:
		len8 = True
		while len8 is True:
			s2 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
			s2 = '%s'%s2
			data = "%x" % (int(s1, 16) ^ int(s2, 16))
			if len(data) is 8 and str('00') not in str(data) and str('00') not in str(s2):
				values_xor += str(s2+'='+data+'_z3r0_')
				len8 = False
	values_xor = values_xor.rsplit('_z3r0_')[:-1]
	print values_xor
	return shellcode
'''
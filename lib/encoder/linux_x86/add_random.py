#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
import random,binascii,string
chars = string.digits + string.ascii_letters
def start(shellcode,job):
	if 'chmod(' in job:	
		t = True
		eax = str('0x0f')
		while t:
			eax_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(1)))
			eax_1 = str('0') + str(eax_1[1])
			eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
			if eax>eax_1:
				if '00' not in str(eax_1) and '00' not in str(eax_2):
					t = False
		eax = 'push   $%s'%(str(eax))
		eax_xor = 'push $0x%s\npop %%eax\npush $0x%s\npop %%ebx\nadd %%eax,%%ebx\npush %%ebx\n'%(eax_1,eax_2)
		shellcode = shellcode.replace(eax,eax_xor)
		ecx = str(shellcode.rsplit('\n')[8])
		ecx_value = str(shellcode.rsplit('\n')[8].rsplit()[1][1:])
		t = True
		while t:
			ecx_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
			ecx_2 = "%x" % (int(ecx_value, 16) - int(ecx_1, 16))
			if '00' not in str(ecx_1) and '00' not in str(ecx_2) and len(ecx_1) >= 7 and len(ecx_2) >= 7 and '-' in ecx_2:
				t = False
		ecx_2 = ecx_2.replace('-','')
		ecx_xor = 'push $0x%s\npop %%ebx\npush $0x%s\npop %%ecx\nneg %%ecx\nadd %%ecx,%%ebx\npush %%ebx\n_z3r0d4y_\n'%(str(ecx_1),str(ecx_2))
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
			t = True
			while t:
				if 'push $0x' in l:
					ebx = l.rsplit()[1][1:]
					ebx_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
					ebx_2 = "%x" % (int(ebx[2:], 16) - int(ebx_1, 16))
					if '00' not in str(ebx_1) and '00' not in str(ebx_2) and '-' in ebx_2 and len(ebx_2) >=7 and len(ebx_1) >= 7 and '-' not in ebx_1:
						ebx_2 = ebx_2.replace('-','')
						command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%edx\nadd %%ebx,%%edx\npush %%edx\n'%(str(ebx_1),str(ebx_2))
						middle = middle.replace(l,command)
						t = False
				else:
					t = False
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
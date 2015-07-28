#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
def start(shellcode,job):
	if 'chmod(' in job:		
		eax = str('0x0f')
		eax_2 = '%x'%(int('0f',16) - int('01',16))
		eax = 'push   $%s'%(str(eax))
		eax_inc = 'push $0x%s\npop %%eax\ninc %%eax\npush %%eax'%(eax_2)
		shellcode = shellcode.replace(eax,eax_inc)
		ecx = str(shellcode.rsplit('\n')[5])
		ecx_value = str(shellcode.rsplit('\n')[5].rsplit()[1][1:])
		ecx_2 = "%x" % (int(ecx_value, 16) - int('01',16))
		ecx_inc = 'push $0x%s\npop %%ebx\ninc %%ebx\npush %%ebx\n_z3r0d4y_\n'%(str(ecx_2))
		shellcode = shellcode.replace(ecx,ecx_inc)
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
				ebx_2 = "%x" % (int(ebx, 16) - int('01',16))
				command = 'push $0x%s\npop %%ebx\ninc %%ebx\npush %%ebx'%(str(ebx_2))
				middle = middle.replace(l,command)
		shellcode = start + middle + end
	if 'dir_create(' in job:
		shellcode = 'N' + shellcode
	if 'download_execute(' in job:
		shellcode = 'N' + shellcode
	if 'download(' in job:
		shellcode = 'N' + shellcode
	if 'exec(' in job:
		shellcode = 'N' + shellcode
	if 'file_create(' in job:
		shellcode = 'N' + shellcode
	if 'script_executor(' in job:
		shellcode = 'N' + shellcode
	if 'system(' in job:
		shellcode = 'N' + shellcode
	if 'write(' in job:
		shellcode = 'N' + shellcode 
	return shellcode

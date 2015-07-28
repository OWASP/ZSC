#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
def start(type,shellcode,job):
	if 'chmod(' in job:	
		eax = str('0x0f')
		times = int(type.rsplit('dec_')[1])
		eax_2 = '%x'%(int('0f',16))
		n = 0
		while n<times:
			eax_2 = '%x'%(int(eax_2,16) + int('01',16))
			n+= 1
		eax = 'push   $%s'%(str(eax))
		dec_str = '\ndec %eax' * times
		neg = 0
		if '-' in eax_2:
			eax_2 = eax_2.replace('-','')
			neg = 1
		if neg is 0:
			eax_dec = 'push $0x%s\npop %%eax%s\npush %%eax'%(eax_2,dec_str)
			plus = times - 1
		if neg is 1:
			eax_dec = 'push $0x%s\npop %%eax\nneg %%eax%s\npush %%eax'%(eax_2,dec_str)
			plus = times
		shellcode = shellcode.replace(eax,eax_dec)
		ecx = str(shellcode.rsplit('\n')[5+plus])
		ecx_value = str(shellcode.rsplit('\n')[5+plus].rsplit()[1][1:])
		ecx_2 = "%x" % (int(ecx_value, 16))
		n = 0
		while n<times:
			ecx_2 = '%x'%(int(ecx_2,16) + int('01',16))
			n+= 1
		neg = 0
		dec_str = '\ndec %ebx' * times
		if '-' in ecx_2:
			ecx_2 = ecx_2.replace('-','')
			neg = 1
		if neg is 0:
			ecx_dec = 'push $0x%s\npop %%ebx%s\npush %%ebx\n_z3r0d4y_\n'%(str(ecx_2),dec_str)
		if neg is 1:
			ecx_dec = 'push $0x%s\npop %%ebx\nneg %%ebx%s\npush %%ebx\n_z3r0d4y_\n'%(str(ecx_2),dec_str)
		shellcode = shellcode.replace(ecx,ecx_dec)
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
				ebx_2 = "%x" % (int(ebx, 16))
				n = 0 
				while n<times:
					ebx_2 = '%x'%(int(ebx_2,16) + int('01',16))
					n+=1
				dec_str = '\ndec %ebx' * times
				neg = 0 
				if '-' in ebx_2:
					ecx_2 = ecx_2.replace('-','')
					neg = 1
				if neg is 0:
					command = 'push $0x%s\npop %%ebx%s\npush %%ebx'%(str(ebx_2),dec_str)
				if neg is 1:
					command = 'push $0x%s\npop %%ebx\nneg %%ebx%s\npush %%ebx'%(str(ebx_2),dec_str)
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

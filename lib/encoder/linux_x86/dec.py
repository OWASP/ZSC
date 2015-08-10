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
		eax_2 = '%x'%(int('0f',16) + int('01',16))
		eax = 'push   $%s'%(str(eax))
		eax_dec = 'push $0x%s\npop %%eax\ndec %%eax\npush %%eax'%(eax_2)
		shellcode = shellcode.replace(eax,eax_dec)
		ecx = str(shellcode.rsplit('\n')[5])
		ecx_value = str(shellcode.rsplit('\n')[5].rsplit()[1][1:])
		ecx_2 = "%x" % (int(ecx_value, 16) + int('01',16))
		ecx_dec = 'push $0x%s\npop %%ebx\ndec %%ebx\npush %%ebx\n_z3r0d4y_\n'%(str(ecx_2))
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
				ebx_2 = "%x" % (int(ebx, 16) + int('01',16))
				command = 'push $0x%s\npop %%ebx\ndec %%ebx\npush %%ebx'%(str(ebx_2))
				middle = middle.replace(l,command)
		shellcode = start + middle + end
	if 'dir_create(' in job:
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax = str('0xb')
		eax_2 = "%x" % (int(eax, 16) + int('01', 16))
		eax_add = 'push $0x%s\npop %%eax\ndec %%eax\n'%(eax_2)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_add+'\ncltd\n')	
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				ebx_2 = "%x" % (int(data, 16) + int('01', 16))
				command = '\npush $0x%s\npop %%eax\ndec %%eax\npush %%eax\n'%(str(ebx_2))
				shellcode = shellcode.replace(line,command)
	if 'download_execute(' in job:
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax = str('0xb')
		eax_2 = "%x" % (int(eax, 16) + int('01', 16))
		eax_add = 'push $0x%s\npop %%eax\ndec %%eax\n'%(eax_2)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_add+'\ncltd\n')	
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				ebx_2 = "%x" % (int(data, 16) + int('01', 16))
				command = '\npush $0x%s\npop %%eax\ndec %%eax\npush %%eax\n'%(str(ebx_2))
				shellcode = shellcode.replace(line,command)
	if 'download(' in job:
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax = str('0xb')
		eax_2 = "%x" % (int(eax, 16) + int('01', 16))
		eax_add = 'push $0x%s\npop %%eax\ndec %%eax\n'%(eax_2)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_add+'\ncltd\n')	
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				ebx_2 = "%x" % (int(data, 16) + int('01', 16))
				command = '\npush $0x%s\npop %%eax\ndec %%eax\npush %%eax\n'%(str(ebx_2))
				shellcode = shellcode.replace(line,command)
	if 'exec(' in job:
		shellcode = 'N' + shellcode
	if 'file_create(' in job:
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax = str('0xb')
		eax_2 = "%x" % (int(eax, 16) + int('01', 16))
		eax_add = 'push $0x%s\npop %%eax\ndec %%eax\n'%(eax_2)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_add+'\ncltd\n')	
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				ebx_2 = "%x" % (int(data, 16) + int('01', 16))
				command = '\npush $0x%s\npop %%eax\ndec %%eax\npush %%eax\n'%(str(ebx_2))
				shellcode = shellcode.replace(line,command)
	if 'script_executor(' in job:
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax = str('0xb')
		eax_2 = "%x" % (int(eax, 16) + int('01', 16))
		eax_add = 'push $0x%s\npop %%eax\ndec %%eax\n'%(eax_2)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_add+'\ncltd\n')	
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				ebx_2 = "%x" % (int(data, 16) + int('01', 16))
				command = '\npush $0x%s\npop %%eax\ndec %%eax\npush %%eax\n'%(str(ebx_2))
				shellcode = shellcode.replace(line,command)
	if 'system(' in job:
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax = str('0xb')
		eax_2 = "%x" % (int(eax, 16) + int('01', 16))
		eax_add = 'push $0x%s\npop %%eax\ndec %%eax\n'%(eax_2)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_add+'\ncltd\n')	
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				ebx_2 = "%x" % (int(data, 16) + int('01', 16))
				command = '\npush $0x%s\npop %%eax\ndec %%eax\npush %%eax\n'%(str(ebx_2))
				shellcode = shellcode.replace(line,command)
	if 'write(' in job:
		shellcode = 'N' + shellcode
	return shellcode

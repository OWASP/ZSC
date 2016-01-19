#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
def start(shellcode,job):
	if 'chmod' == job:	
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
	elif 'dir_create' == job:
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
	elif 'download_execute' == job:
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
	elif 'download' == job:
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
	elif 'exec' == job:
		t = True
		eax = str('0x46909090')
		eax_2 = "%x" % (int(eax, 16) + int('0x01', 16))
		A = 0	
		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_add = 'push $0x%s\npop %%eax\ndec %%eax\nneg %%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n_z3r0d4y_'%(eax_2)

		if A is 0:
			eax_add = 'push $0x%s\npop %%eax\ndec %%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n_z3r0d4y_'%(eax_2)
		shellcode = shellcode.replace('mov    $0x46,%al',eax_add)
			
		A = 0
		for line in shellcode.rsplit('\n'):
			if '_z3r0d4y_' in line:
				A = 1
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14 and A is 1:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				ebx_2 = "%x" % (int(data, 16) + int('0x01', 16))
				command = '\npush $0x%s\npop %%ebx\ndec %%ebx\npush %%ebx\n'%(str(ebx_2))
				shellcode = shellcode.replace(line,command)
		shellcode = shellcode.replace('_z3r0d4y_','')
	elif 'file_create' == job:
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
	elif 'script_executor' == job:
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
	elif 'system' == job:
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
	elif 'write' == job:
		eax = str('0x5')
		eax_2 = "%x" % (int(eax, 16) + int('0x01', 16))
		eax_add = 'push $0x%s\npop %%eax\ndec %%eax\n'%(eax_2)
		shellcode = shellcode.replace('push   $0x5\npop    %eax',eax_add)

		eax = str('0x4')
		eax_2 = "%x" % (int(eax, 16) + int('0x01', 16))
		eax_add = 'push $0x%s\npop %%eax\ndec %%eax\n'%(eax_2)
		shellcode = shellcode.replace('push   $0x4\npop    %eax',eax_add)
		A = 1
		for line in shellcode.rsplit('\n'):
			if 'mov    %esp,%ebx' in line:
				A = 1
				shellcode = shellcode.replace(line,'\nmov    %esp,%ebx\n_z3r0d4y_\n')
			if A is 0:
				if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
					data = line.rsplit('push')[1].rsplit('$0x')[1]
					ebx_2 = "%x" % (int(data, 16) + int('0x01', 16))
					command = '\npush $0x%s\npop %%ebx\ndec %%ebx\npush %%ebx\n'%(str(ebx_2))
					shellcode = shellcode.replace(line,command)
		shellcode = shellcode.replace('_z3r0d4y_','')
		eax = str('4014141')
		eax_2 = "%x" % (int(eax, 16) + int('0x01', 16))
		eax_add = 'push $0x%s\npop %%ecx\ndec %%ecx\n'%(eax_2)
		shellcode = shellcode.replace('push   $0x4014141\npop    %ecx',eax_add+'\n_z3r0d4y_\n').replace('mov %esp,%ecx','\n_z3r0|d4y_\nmov %esp,%ecx\n')
		A = 1
		for line in shellcode.rsplit('\n'):
			if '_z3r0d4y_' in line:
				A = 0
			if '_z3r0|d4y_' in line:
				A = 2
			if A is 0:
				if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
					data = line.rsplit('push')[1].rsplit('$0x')[1]
					ebx_2 = "%x" % (int(data, 16) + int('0x01', 16))
					command = '\npush $0x%s\npop %%ecx\ndec %%ecx\npush %%ecx\n'%(str(ebx_2))
					shellcode = shellcode.replace(line,command)
			if A is 2:
				if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
					data = line.rsplit('push')[1].rsplit('$0x')[1]
					ebx_2 = "%x" % (int(data, 16) + int('0x01', 16))
					command = '\npush $0x%s\npop %%edx\ndec %%edx\npush %%edx\n'%(str(ebx_2))
					shellcode = shellcode.replace(line,command)
		shellcode = shellcode.replace('_z3r0d4y_','').replace('_z3r0|d4y_','')
		eax = str('0b909090')
		eax_2 = "%x" % (int(eax, 16) + int('0x01', 16))
		eax = 'push   $%s'%(str(eax))	
		eax_add = 'push $0x%s\npop %%edx\ndec %%edx\n'%(eax_2)
		shellcode = shellcode.replace('push $0x0b909090\n\npop %edx\n',eax_add)
	return shellcode

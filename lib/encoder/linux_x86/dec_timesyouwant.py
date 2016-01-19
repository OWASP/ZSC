#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
def start(type,shellcode,job):
	if 'chmod' == job:	
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
	elif 'dir_create' == job:
		times = int(type.rsplit('dec_')[1])
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax_2 = str('0xb')
		n = 0
		while n<times:
			eax_2 = "%x" % (int(eax_2, 16) + int('01', 16))
			n+= 1
		dec = 'dec %eax\n' * n
		eax_add = 'push $0x%s\npop %%eax\n%s\n'%(eax_2,dec)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_add+'\ncltd\n')
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				ebx_2 = line.rsplit('push')[1].rsplit('$0x')[1]
				n = 0
				while n<times:
					ebx_2 = "%x" % (int(ebx_2, 16) + int('01', 16))
					n+= 1
				dec = 'dec %eax\n' * n
				command = '\npush $0x%s\npop %%eax\n%spush %%eax\n'%(str(ebx_2),str(dec))
				shellcode = shellcode.replace(line,command)
	elif 'download_execute' == job:
		times = int(type.rsplit('dec_')[1])
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax_2 = str('0xb')
		n = 0
		while n<times:
			eax_2 = "%x" % (int(eax_2, 16) + int('01', 16))
			n+= 1
		dec = 'dec %eax\n' * n
		eax_add = 'push $0x%s\npop %%eax\n%s\n'%(eax_2,dec)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_add+'\ncltd\n')
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				ebx_2 = line.rsplit('push')[1].rsplit('$0x')[1]
				n = 0
				while n<times:
					ebx_2 = "%x" % (int(ebx_2, 16) + int('01', 16))
					n+= 1
				dec = 'dec %eax\n' * n
				command = '\npush $0x%s\npop %%eax\n%spush %%eax\n'%(str(ebx_2),str(dec))
				shellcode = shellcode.replace(line,command)
	elif 'download' == job:
		times = int(type.rsplit('dec_')[1])
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax_2 = str('0xb')
		n = 0
		while n<times:
			eax_2 = "%x" % (int(eax_2, 16) + int('01', 16))
			n+= 1
		dec = 'dec %eax\n' * n
		eax_add = 'push $0x%s\npop %%eax\n%s\n'%(eax_2,dec)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_add+'\ncltd\n')
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				ebx_2 = line.rsplit('push')[1].rsplit('$0x')[1]
				n = 0
				while n<times:
					ebx_2 = "%x" % (int(ebx_2, 16) + int('01', 16))
					n+= 1
				dec = 'dec %eax\n' * n
				command = '\npush $0x%s\npop %%eax\n%spush %%eax\n'%(str(ebx_2),str(dec))
				shellcode = shellcode.replace(line,command)
	elif 'exec' == job:
		times = int(type.rsplit('dec_')[1])
		t = True
		eax_2,eax = str('0x46909090'),str('0x46909090')
		n = 0
		while n<times:
			eax_2 = "%x" % (int(eax_2, 16) + int('0x01', 16))
			n+=1
		dec = 'dec %eax\n' * n
		A = 0	
		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_add = 'push $0x%s\npop %%eax\n%s\nneg %%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n_z3r0d4y_'%(eax_2,dec)

		if A is 0:
			eax_add = 'push $0x%s\npop %%eax\n%s\nshr $0x10,%%eax\nshr $0x08,%%eax\n_z3r0d4y_'%(eax_2,dec)
		shellcode = shellcode.replace('mov    $0x46,%al',eax_add)
			
		A = 0
		for line in shellcode.rsplit('\n'):
			if '_z3r0d4y_' in line:
				A = 1
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14 and A is 1:
				ebx_2 = line.rsplit('push')[1].rsplit('$0x')[1]
				n = 0
				while n<times:
					ebx_2 = "%x" % (int(ebx_2, 16) + int('0x01', 16))
					n+=1
				dec = 'dec %ebx\n' * n
				command = '\npush $0x%s\npop %%ebx\n%s\npush %%ebx\n'%(str(ebx_2),dec)
				shellcode = shellcode.replace(line,command)
		shellcode = shellcode.replace('_z3r0d4y_','')
	elif 'file_create' == job:
		times = int(type.rsplit('dec_')[1])
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax_2 = str('0xb')
		n = 0
		while n<times:
			eax_2 = "%x" % (int(eax_2, 16) + int('01', 16))
			n+= 1
		dec = 'dec %eax\n' * n
		eax_add = 'push $0x%s\npop %%eax\n%s\n'%(eax_2,dec)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_add+'\ncltd\n')
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				ebx_2 = line.rsplit('push')[1].rsplit('$0x')[1]
				n = 0
				while n<times:
					ebx_2 = "%x" % (int(ebx_2, 16) + int('01', 16))
					n+= 1
				dec = 'dec %eax\n' * n
				command = '\npush $0x%s\npop %%eax\n%spush %%eax\n'%(str(ebx_2),str(dec))
				shellcode = shellcode.replace(line,command)
	elif 'script_executor' == job:
		times = int(type.rsplit('dec_')[1])
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax_2 = str('0xb')
		n = 0
		while n<times:
			eax_2 = "%x" % (int(eax_2, 16) + int('01', 16))
			n+= 1
		dec = 'dec %eax\n' * n
		eax_add = 'push $0x%s\npop %%eax\n%s\n'%(eax_2,dec)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_add+'\ncltd\n')
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				ebx_2 = line.rsplit('push')[1].rsplit('$0x')[1]
				n = 0
				while n<times:
					ebx_2 = "%x" % (int(ebx_2, 16) + int('01', 16))
					n+= 1
				dec = 'dec %eax\n' * n
				command = '\npush $0x%s\npop %%eax\n%spush %%eax\n'%(str(ebx_2),str(dec))
				shellcode = shellcode.replace(line,command)
	elif 'system' == job:
		times = int(type.rsplit('dec_')[1])
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax_2 = str('0xb')
		n = 0
		while n<times:
			eax_2 = "%x" % (int(eax_2, 16) + int('01', 16))
			n+= 1
		dec = 'dec %eax\n' * n
		eax_add = 'push $0x%s\npop %%eax\n%s\n'%(eax_2,dec)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_add+'\ncltd\n')
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				ebx_2 = line.rsplit('push')[1].rsplit('$0x')[1]
				n = 0
				while n<times:
					ebx_2 = "%x" % (int(ebx_2, 16) + int('01', 16))
					n+= 1
				dec = 'dec %eax\n' * n
				command = '\npush $0x%s\npop %%eax\n%spush %%eax\n'%(str(ebx_2),str(dec))
				shellcode = shellcode.replace(line,command)
	elif 'write' == job:
		times = int(type.rsplit('dec_')[1])
		eax_2 = str('0x5')
		n = 0
		while n<times:
			eax_2 = "%x" % (int(eax_2, 16) + int('0x01', 16))
			n+=1
		dec = 'dec %eax\n' * n
		eax_add = 'push $0x%s\npop %%eax\n%s\n'%(eax_2,dec)
		shellcode = shellcode.replace('push   $0x5\npop    %eax',eax_add)
		eax_2 = str('0x4')
		n = 0
		while n<times:
			eax_2 = "%x" % (int(eax_2, 16) + int('0x01', 16))
			n+=1
		dec = 'dec %eax\n' * n
		eax_add = 'push $0x%s\npop %%eax\n%s\n'%(eax_2,dec)
		shellcode = shellcode.replace('push   $0x4\npop    %eax',eax_add)
		A = 1
		for line in shellcode.rsplit('\n'):
			if 'mov    %esp,%ebx' in line:
				A = 1
				shellcode = shellcode.replace(line,'\nmov    %esp,%ebx\n_z3r0d4y_\n')
			if A is 0:
				if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
					ebx_2 = line.rsplit('push')[1].rsplit('$0x')[1]
					n = 0
					while n<times:
						ebx_2 = "%x" % (int(ebx_2, 16) + int('0x01', 16))
						n+=1
					dec = 'dec %ebx\n' * n
					command = '\npush $0x%s\npop %%ebx\n%s\npush %%ebx\n'%(str(ebx_2),dec)
					shellcode = shellcode.replace(line,command)
		shellcode = shellcode.replace('_z3r0d4y_','')
		eax_2 = str('4014141')
		n = 0
		while n<times:
			eax_2 = "%x" % (int(eax_2, 16) + int('0x01', 16))
			n+=1
		dec = 'dec %ecx\n' * n
		eax_add = 'push $0x%s\npop %%ecx\n%s\n'%(eax_2,dec)
		shellcode = shellcode.replace('push   $0x4014141\npop    %ecx',eax_add+'\n_z3r0d4y_\n').replace('mov %esp,%ecx','\n_z3r0|d4y_\nmov %esp,%ecx\n')
		A = 1
		for line in shellcode.rsplit('\n'):
			if '_z3r0d4y_' in line:
				A = 0
			if '_z3r0|d4y_' in line:
				A = 2
			if A is 0:
				if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
					ebx_2 = line.rsplit('push')[1].rsplit('$0x')[1]
					n = 0
					while n<times:
						ebx_2 = "%x" % (int(ebx_2, 16) + int('0x01', 16))
						n+=1
					dec = 'dec %ecx\n' * n
					command = '\npush $0x%s\npop %%ecx\n%s\npush %%ecx\n'%(str(ebx_2),dec)
					shellcode = shellcode.replace(line,command)
			if A is 2:
				if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
					ebx_2 = line.rsplit('push')[1].rsplit('$0x')[1]
					n = 0
					while n<times:
						ebx_2 = "%x" % (int(ebx_2, 16) + int('0x01', 16))
						n+=1
					dec = 'dec %ecx\n' * n
					command = '\npush $0x%s\npop %%edx\n%s\npush %%edx\n'%(str(ebx_2),dec)
					shellcode = shellcode.replace(line,command)
		shellcode = shellcode.replace('_z3r0d4y_','').replace('_z3r0|d4y_','')
		eax_2 = str('0b909090')
		n = 0
		while n<times:
			eax_2 = "%x" % (int(eax_2, 16) + int('0x01', 16))
			n+=1
		eax = 'push   $%s'%(str(eax_2))	
		dec = 'dec %edx\n' * n
		eax_add = 'push $0x%s\npop %%edx\n%s\n'%(eax_2,dec)
		shellcode = shellcode.replace('push $0x0b909090\n\npop %edx\n',eax_add)
	return shellcode

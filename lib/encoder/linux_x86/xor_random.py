#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder

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
			eax_2 = "%x" % (int(eax, 16) ^ int(eax_1, 16))
			if '00' not in eax_1 and '00' not in eax_2:
				t = False
		eax = 'push   $%s'%(str(eax))
		eax_xor = 'push $0x%s\npop %%eax\npush $0x%s\npop %%ebx\nxor %%eax,%%ebx\npush %%ebx\n'%(eax_1,eax_2)
		shellcode = shellcode.replace(eax,eax_xor)
		ecx = str(shellcode.rsplit('\n')[8])
		ecx_value = str(shellcode.rsplit('\n')[8].rsplit()[1][1:])
		t = True
		while t:
			ecx_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
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
				ebx_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
				ebx_2 = "%x" % (int(ebx, 16) ^ int(ebx_1, 16))
				command = 'push $0x%s\npop %%ebx\npush $0x%s\npop %%edx\nxor %%ebx,%%edx\npush %%edx'%(str(ebx_1),str(ebx_2))
				middle = middle.replace(l,command)
		shellcode = start + middle + end
	if 'dir_create(' in job:
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax = str('0xb')
		while t:
			eax_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(1)))
			eax_1 = str('0') + str(eax_1[1])
			eax_2 = "%x" % (int(eax, 16) ^ int(eax_1, 16))
			if eax>eax_1:
				if '00' not in str(eax_1) and '00' not in str(eax_2):
					t = False
		A = 0	
		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_xor = 'push $0x%s\npop %%eax\nneg %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		if A is 0:
			eax_xor = 'push $0x%s\npop %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_xor+'\ncltd\n')	
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				t = True
				while t:
					ebx_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
					ebx_2 = "%x" % (int(data, 16) ^ int(ebx_1, 16))

					
					if str('00') not in str(ebx_1) and str('00') not in str(ebx_2) and len(ebx_2) >=7 and len(ebx_1) >= 7 and '-' not in ebx_1:
						ebx_2 = ebx_2.replace('-','')
						command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nxor %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
						shellcode = shellcode.replace(line,command)
						t = False
	if 'download_execute(' in job:
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax = str('0xb')
		while t:
			eax_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(1)))
			eax_1 = str('0') + str(eax_1[1])
			eax_2 = "%x" % (int(eax, 16) ^ int(eax_1, 16))
			if eax>eax_1:
				if '00' not in str(eax_1) and '00' not in str(eax_2):
					t = False
		A = 0	
		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_xor = 'push $0x%s\npop %%eax\nneg %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		if A is 0:
			eax_xor = 'push $0x%s\npop %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_xor+'\ncltd\n')	
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				t = True
				while t:
					ebx_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
					ebx_2 = "%x" % (int(data, 16) ^ int(ebx_1, 16))

					
					if str('00') not in str(ebx_1) and str('00') not in str(ebx_2) and len(ebx_2) >=7 and len(ebx_1) >= 7 and '-' not in ebx_1:
						ebx_2 = ebx_2.replace('-','')
						command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nxor %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
						shellcode = shellcode.replace(line,command)
						t = False
	if 'download(' in job:
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax = str('0xb')
		while t:
			eax_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(1)))
			eax_1 = str('0') + str(eax_1[1])
			eax_2 = "%x" % (int(eax, 16) ^ int(eax_1, 16))
			if eax>eax_1:
				if '00' not in str(eax_1) and '00' not in str(eax_2):
					t = False
		A = 0	
		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_xor = 'push $0x%s\npop %%eax\nneg %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		if A is 0:
			eax_xor = 'push $0x%s\npop %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_xor+'\ncltd\n')	
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				t = True
				while t:
					ebx_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
					ebx_2 = "%x" % (int(data, 16) ^ int(ebx_1, 16))

					
					if str('00') not in str(ebx_1) and str('00') not in str(ebx_2) and len(ebx_2) >=7 and len(ebx_1) >= 7 and '-' not in ebx_1:
						ebx_2 = ebx_2.replace('-','')
						command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nxor %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
						shellcode = shellcode.replace(line,command)
						t = False
	if 'exec(' in job:
		t = True
		eax = str('0x46')
		while t:
			eax_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(1)))
			eax_1 = str('0') + str(eax_1[1])
			eax_2 = "%x" % (int(eax, 16) ^ int(eax_1, 16))
			if eax>eax_1:
				if '00' not in str(eax_1) and '00' not in str(eax_2):
					t = False

		A = 0	
		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_xor = 'push $0x%s\npop %%eax\nneg %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)

		if A is 0:
			eax_xor = 'push $0x%s\npop %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('mov    $0x46,%al',eax_xor)	
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				t = True
				while t:
					ebx_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
					ebx_2 = "%x" % (int(data, 16) ^ int(ebx_1, 16))
					
					if str('00') not in str(ebx_1) and str('00') not in str(ebx_2) and len(ebx_2) >=7 and len(ebx_1) >= 7 and '-' not in ebx_1:
						ebx_2 = ebx_2.replace('-','')
						command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nxor %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
						shellcode = shellcode.replace(line,command)
						t = False
	if 'file_create(' in job:
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax = str('0xb')
		while t:
			eax_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(1)))
			eax_1 = str('0') + str(eax_1[1])
			eax_2 = "%x" % (int(eax, 16) ^ int(eax_1, 16))
			if eax>eax_1:
				if '00' not in str(eax_1) and '00' not in str(eax_2):
					t = False
		A = 0	
		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_xor = 'push $0x%s\npop %%eax\nneg %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		if A is 0:
			eax_xor = 'push $0x%s\npop %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_xor+'\ncltd\n')	
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				t = True
				while t:
					ebx_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
					ebx_2 = "%x" % (int(data, 16) ^ int(ebx_1, 16))

					
					if str('00') not in str(ebx_1) and str('00') not in str(ebx_2) and len(ebx_2) >=7 and len(ebx_1) >= 7 and '-' not in ebx_1:
						ebx_2 = ebx_2.replace('-','')
						command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nxor %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
						shellcode = shellcode.replace(line,command)
						t = False
	if 'script_executor(' in job:
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax = str('0xb')
		while t:
			eax_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(1)))
			eax_1 = str('0') + str(eax_1[1])
			eax_2 = "%x" % (int(eax, 16) ^ int(eax_1, 16))
			if eax>eax_1:
				if '00' not in str(eax_1) and '00' not in str(eax_2):
					t = False
		A = 0	
		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_xor = 'push $0x%s\npop %%eax\nneg %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		if A is 0:
			eax_xor = 'push $0x%s\npop %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_xor+'\ncltd\n')	
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				t = True
				while t:
					ebx_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
					ebx_2 = "%x" % (int(data, 16) ^ int(ebx_1, 16))

					
					if str('00') not in str(ebx_1) and str('00') not in str(ebx_2) and len(ebx_2) >=7 and len(ebx_1) >= 7 and '-' not in ebx_1:
						ebx_2 = ebx_2.replace('-','')
						command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nxor %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
						shellcode = shellcode.replace(line,command)
						t = False
	if 'system(' in job:
		shellcode = 'xor %edx,%edx\n' + shellcode.replace('push   $0xb\npop    %eax\ncltd','').replace('push   %ebx\nmov    %esp,%ecx','push   %ebx\nmov    %esp,%ecx'+'\n'+'push   $0xb\npop    %eax\ncltd')
		t = True
		eax = str('0xb')
		while t:
			eax_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(1)))
			eax_1 = str('0') + str(eax_1[1])
			eax_2 = "%x" % (int(eax, 16) ^ int(eax_1, 16))
			if eax>eax_1:
				if '00' not in str(eax_1) and '00' not in str(eax_2):
					t = False
		A = 0	
		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_xor = 'push $0x%s\npop %%eax\nneg %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		if A is 0:
			eax_xor = 'push $0x%s\npop %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',eax_xor+'\ncltd\n')	
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				t = True
				while t:
					ebx_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
					ebx_2 = "%x" % (int(data, 16) ^ int(ebx_1, 16))
					
					if str('00') not in str(ebx_1) and str('00') not in str(ebx_2) and len(ebx_2) >=7 and len(ebx_1) >= 7 and '-' not in ebx_1:
						ebx_2 = ebx_2.replace('-','')
						command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nxor %%ebx,%%eax\npush %%eax\n'%(str(ebx_1),str(ebx_2))
						shellcode = shellcode.replace(line,command)
						t = False
	if 'write(' in job:
		t = True
		eax = str('0x5')
		while t:
			eax_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(1)))
			eax_1 = str('0') + str(eax_1[1])
			eax_2 = "%x" % (int(eax, 16) ^ int(eax_1, 16))
			if eax_1 != eax:
				if eax>eax_1:
					if '00' not in str(eax_1) and '00' not in str(eax_2):
						t = False
		A = 0	
		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_xor = 'push $0x%s\npop %%eax\nneg %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		if A is 0:
			eax_xor = 'push $0x%s\npop %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('push   $0x5\npop    %eax',eax_xor)
		
		t = True
		eax = str('0x4')
		while t:
			eax_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(1)))
			eax_1 = str('0') + str(eax_1[1])
			eax_2 = "%x" % (int(eax, 16) ^ int(eax_1, 16))
			if eax_1 != eax:
				if eax>eax_1:
					if str('00') not in str(eax_1) and str('00') not in str(eax_2):
						t = False
		A = 0	
		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_xor = 'push $0x%s\npop %%eax\nneg %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		if A is 0:
			eax_xor = 'push $0x%s\npop %%eax\nxor $0x%s,%%eax\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('push   $0x4\npop    %eax',eax_xor)

				

		A = 0
		for line in shellcode.rsplit('\n'):
			if 'mov    %esp,%ebx' in line:
				A = 1
				shellcode = shellcode.replace(line,'\nmov    %esp,%ebx\n_z3r0d4y_\n')
			if A is 0:
				if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
					data = line.rsplit('push')[1].rsplit('$0x')[1]
					t = True
					while t:
						ebx_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
						ebx_2 = "%x" % (int(data, 16) ^ int(ebx_1, 16))
						
						if str('00') not in str(ebx_1) and str('00') not in str(ebx_2) and len(ebx_2) >=7 and len(ebx_1) >= 7 and '-' not in ebx_1 and ebx_1 != data:
							ebx_2 = ebx_2.replace('-','')
							command = '\npush $0x%s\npop %%ebx\nxor $0x%s,%%ebx\npush %%ebx\n'%(str(ebx_2),str(ebx_1))
							shellcode = shellcode.replace(line,command)
							t = False
		shellcode = shellcode.replace('_z3r0d4y_','')
		
		t = True
		eax = str('4014141')
		while t:
			eax_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
			eax_2 = "%x" % (int(eax, 16) ^ int(eax_1, 16))
			if eax_1 != eax:
				if eax>eax_1:
					if '00' not in str(eax_1) and '00' not in str(eax_2):
						t = False
		A = 0	
		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_xor = 'push $0x%s\npop %%ecx\nneg %%ecx\nxor $0x%s,%%ecx\n'%(eax_2,eax_1)
		if A is 0:
			eax_xor = 'push $0x%s\npop %%ecx\nxor $0x%s,%%ecx\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('push   $0x4014141\npop    %ecx',eax_xor+'\n_z3r0d4y_\n').replace('push $0x06909090','\n_z3r0|d4y_\npush $0x06909090\n')
		A = 1
		for line in shellcode.rsplit('\n'):
			if '_z3r0d4y_' in line:
				A = 0
			if '_z3r0|d4y_' in line:
				A = 1
			if A is 0:
				if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
					data = line.rsplit('push')[1].rsplit('$0x')[1]
					t = True
					while t:
						ebx_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
						ebx_2 = "%x" % (int(data, 16) ^ int(ebx_1, 16))
						if ebx_1 != data and str('00') not in str(ebx_1) and str('00') not in str(ebx_2) and len(ebx_2) >=7 and len(ebx_1) >= 7 and '-' not in ebx_1:
							ebx_2 = ebx_2.replace('-','')
							command = '\npush $0x%s\npop %%ecx\nxor $0x%s,%%ecx\npush %%ecx\n'%(str(ebx_2),str(ebx_1))
							shellcode = shellcode.replace(line,command)
							t = False
		shellcode = shellcode.replace('_z3r0d4y_','').replace('_z3r0|d4y_','')
		t = True
		eax = str('0b909090')
		while t:
			eax_1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
			eax_2 = "%x" % (int(eax, 16) ^ int(eax_1, 16))
			if '00' not in str(eax_1) and '00' not in str(eax_2) and eax_1 != eax:
				t = False
		A = 0	
		eax = 'push   $%s'%(str(eax))	
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-','')
			eax_xor = 'push $0x%s\npop %%edx\nneg %%edx\nxor $0x%s,%%edx\n'%(eax_2,eax_1)
		if A is 0:
			eax_xor = 'push $0x%s\npop %%edx\nxor $0x%s,%%edx\n'%(eax_2,eax_1)
		shellcode = shellcode.replace('push $0x0b909090\n\npop %edx\n',eax_xor)
	return shellcode

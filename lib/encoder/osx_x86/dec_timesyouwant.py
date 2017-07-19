def start(type, shellcode, job):
	if "exec" == job:
		times = int(type.rsplit('dec_')[1])
        t = True
        eax_2, eax = str('0x3b909090'), str('0x3b909090')
        n = 0
        while n < times:
            eax_2 = "%x" % (int(eax_2, 16) + int('0x01', 16))
            n += 1
        dec = 'dec %eax\n' * n
        A = 0
        eax = 'push   $%s' % (str(eax))
        if '-' in eax_2:
            A = 1
            eax_2 = eax_2.replace('-', '')
            eax_add = 'push $0x%s\npop %%eax\n%s\nneg %%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n_z3r0d4y_' % (
                eax_2, dec)

        if A is 0:
            eax_add = 'push $0x%s\npop %%eax\n%s\nshr $0x10,%%eax\nshr $0x08,%%eax\n_z3r0d4y_' % (
                eax_2, dec)
        shellcode = shellcode.replace('mov    $0x3b,%al', eax_add)

        A = 0
        for line in shellcode.rsplit('\n'):
            if '_z3r0d4y_' in line:
                A = 1
            if 'push' in line and '$0x' in line and ',' not in line and len(
                    line) > 14 and A is 1:
                ebx_2 = line.rsplit('push')[1].rsplit('$0x')[1]
                n = 0
                while n < times:
                    ebx_2 = "%x" % (int(ebx_2, 16) + int('0x01', 16))
                    n += 1
                dec = 'dec %ebx\n' * n
                command = '\npush $0x%s\npop %%ebx\n%s\npush %%ebx\n' % (
                    str(ebx_2), dec)
                shellcode = shellcode.replace(line, command)
        shellcode = shellcode.replace('_z3r0d4y_', '')
    if "system" == job:
    	times = int(type.rsplit('dec_')[1])
    	for line in shellcode.rsplit('\n'):
            if 'push' in line and '$0x' in line and ',' not in line and len(
                    line) > 14:
                ebx_2 = line.rsplit('push')[1].rsplit('$0x')[1]
                n = 0
                while n < times:
                    ebx_2 = "%x" % (int(ebx_2, 16) + int('01', 16))
                    n += 1
                dec = 'dec %eax\n' * n
                command = '\npush $0x%s\npop %%eax\n%spush %%eax\n' % (
                    str(ebx_2), str(dec))
                shellcode = shellcode.replace(line, command)

	return shellcode
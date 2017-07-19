#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''


def start(type, shellcode, job):

	if "exec" == job:
		value = str(type.rsplit('xor_')[1][2:])
        t = True
        eax = str('0x3b909090')
        eax_1 = value
        eax_2 = "%x" % (int(eax, 16) ^ int(eax_1, 16))
        A = 0
        eax = 'push   $%s' % (str(eax))
        if '-' in eax_2:
            A = 1
            eax_2 = eax_2.replace('-', '')
            eax_xor = 'push $0x%s\npop %%eax\nneg %%eax\nxor $0x%s,%%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n_z3r0d4y_' % (
                eax_2, eax_1)

        if A is 0:
            eax_xor = 'push $0x%s\npop %%eax\nxor $0x%s,%%eax\nshr $0x10,%%eax\nshr $0x08,%%eax\n_z3r0d4y_' % (
                eax_2, eax_1)
        shellcode = shellcode.replace('mov    $0x3b,%al', eax_xor)
        A = 0
        for line in shellcode.rsplit('\n'):
            if '_z3r0d4y_' in line:
                A = 1
            if 'push' in line and '$0x' in line and ',' not in line and len(
                    line) > 14 and A is 1:
                data = line.rsplit('push')[1].rsplit('$0x')[1]
                t = True
                while t:
                    ebx_1 = value
                    ebx_2 = "%x" % (int(data, 16) ^ int(ebx_1, 16))

                    if str('00') not in str(ebx_1) and str('00') not in str(
                            ebx_2) and len(ebx_2) >= 7 and len(
                                ebx_1) >= 7 and '-' not in ebx_1:
                        ebx_2 = ebx_2.replace('-', '')
                        command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nxor %%ebx,%%eax\npush %%eax\n' % (
                            str(ebx_1), str(ebx_2))
                        shellcode = shellcode.replace(line, command)
                        t = False
        shellcode = shellcode.replace('_z3r0d4y_', '')

	if "system" == job:
		value = str(type.rsplit('xor_')[1][2:])
		for line in shellcode.rsplit('\n'):
            if 'push' in line and '$0x' in line and ',' not in line and len(
                    line) > 14:
                data = line.rsplit('push')[1].rsplit('$0x')[1]
                ebx_1 = value
                ebx_2 = "%x" % (int(data, 16) ^ int(ebx_1, 16))
                A = 0
                if str('-') in str(ebx_2):
                    ebx_2 = ebx_2.replace('-', '')
                    command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nneg %%eax\nxor %%ebx,%%eax\npush %%eax\n' % (
                        str(ebx_1), str(ebx_2))
                    A = 1
                if A is 0:
                    command = '\npush $0x%s\npop %%ebx\npush $0x%s\npop %%eax\nxor %%ebx,%%eax\npush %%eax\n' % (
                        str(ebx_1), str(ebx_2))
                shellcode = shellcode.replace(line, command)

	return shellcode
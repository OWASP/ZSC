#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
import binascii
from core import stack
from core import color
from core.alert import info
from core.compatible import version
_version = version()
replace_values_static = {
	'xor %ebx,%ebx':'31 db',
	'xor %ecx,%ecx':'31 c9',
	'xor %eax,%ebx':'31 c3',
	'xor %ecx,%ebx':'31 cb',
	'xor %ebx,%eax':'31 d8',
	'xor %eax,%eax':'31 c0',
	'xor %ebx,%edx':'31 da',
	'xor %edx,%edx':'31 d2',
	'xor %ebx,%ecx':'31 d9',
	'xor %esi,%esi':'31 f6',
	'xor %eax,%ecx':'31 c1',
	'xor %edi,%edi':'31 ff',
	'mov %esp,%ebx':'89 e3',
	'mov $0x1,%al':'b0 01',
	'mov $0x01,%al':'b0 01',
	'mov $0x1,%bl':'b3 01',
	'mov $0x01,%bl':'b3 01',
	'mov $0xb,%al':'b0 0b',
	'mov %eax,%ebx':'89 c3',
	'mov %esp,%ecx':'89 e1',
	'mov %esp,%esi':'89 e6',
	'mov %esp,%edi':'89 e7',
	'mov %esp,%edx':'89 e2',
	'mov %edx,%esi':'89 d6',
	'mov %eax,%edi':'89 c7',
	'mov %esi,%edx':'89 f2',
	'shr $0x10,%ebx':'c1 eb 10',
	'shr $0x08,%ebx':'c1 eb 08',
	'shr $0x8,%ebx':'c1 eb 08',
	'shr $0x10,%eax':'c1 e8 10',
	'shr $0x08,%eax':'c1 e8 08',
	'shr $0x8,%eax':'c1 e8 08',
	'shr $0x10,%ecx':'c1 e9 10',
	'shr $0x8,%ecx':'c1 e9 08',
	'shr $0x08,%ecx':'c1 e9 08',
	'shr $0x10,%edx':'c1 ea 10',
	'shr $0x8,%edx':'c1 ea 08',
	'shr $0x08,%edx':'c1 ea 08',
	'inc %ecx':'41',
	'add %ecx,%ebx':'01 cb',
	'add %eax,%ebx':'01 c3',
	'add %eax,%ecx':'01 c1',
	'add %ebx,%edx':'01 da',
	'add %ebx,%eax':'01 d8',
	'add %ebx,%ecx':'01 d9',
	'sub %eax,%ecx':'29 c1',
	'sub %ebx,%ecx':'29 d9',
	'push %eax':'50',
	'push %ebx':'53',
	'push %ecx':'51',
	'push %edx':'52',
	'push %esi':'56',
	'push %edi':'57',
	'pop %eax':'58',
	'pop %ebx':'5b',
	'pop %ecx':'59',
	'pop %edx':'5a',
	'dec %ecx':'49',
	'neg %ecx':'f7 d9',
	'neg %eax':'f7 d8',
	'subl $0x61,0x3(%esp)':'83 6c 24 03 61',
	'lods %ds:(%esi),%eax':'ad',
	'add %ebx,%esi':'01 de',
	'push %esp':'54',
	'call *%edx':'ff d2',
	'call *%eax':'ff d0',
	'call *%esi':'ff d6',
	'xchg %eax,%esi':'96',
	'mov %fs:0x30(%ecx),%eax':'64 8b 41 30',
	'mov (%esi,%ecx,2),%cx':'66 8b 0c 4e',
	'mov (%esi,%ecx,4),%edx':'8b 14 8e',
}


def convert(shellcode):
	shellcode = shellcode.replace('\n\n','\n').replace('\n\n','\n').replace('    ',' ').replace('   ',' ').replace('	',' ')
	for data in replace_values_static:
		shellcode = shellcode.replace(data,replace_values_static[data])

	new_shellcode = shellcode.rsplit('\n')
	last = 0
	for line in new_shellcode:
		if 'push $0x' in line:
			if len(line) is 15:
				if _version is 2:
					rep = str('68') + stack.st(str(binascii.a2b_hex(str('0') + str(line.rsplit('$0x')[1]))))
				if _version is 3:
					rep = str('68') + stack.st(str(binascii.a2b_hex(str('0') + line.rsplit('$0x')[1].encode('latin-1')).decode('latin-1')))
				shellcode = shellcode.replace(line,rep)
			if len(line) is 16:
				if _version is 2:
					rep = str('68') + stack.st(str(binascii.a2b_hex(str(line.rsplit('$0x')[1]))))
				if _version is 3:
					rep = str('68') + stack.st(str(binascii.a2b_hex(line.rsplit('$0x')[1].encode('latin-1')).decode('latin-1')))
				shellcode = shellcode.replace(line,rep)

		if 'mov $0x' in line:
			if '%ecx' in line.rsplit(',')[1]:
				if _version is 2:
					rep = str('b9') + stack.st(str(binascii.a2b_hex(line.rsplit('$0x')[1].rsplit(',')[0])))
				if _version is 3:
					rep = str('b9') + stack.st(str(binascii.a2b_hex(line.rsplit('$0x')[1].rsplit(',')[0].encode('latin-1')).decode('latin-1')))
				shellcode = shellcode.replace(line,rep)

		if 'mov 0x' in line:
			if '%eax' in line.rsplit(',')[0] and '%eax' in line.rsplit(',')[1]:
				rep = str('8b 40') + stack.toHex(line.rsplit('0x')[1].rsplit('(')[0])
				shellcode = shellcode.replace(line,rep)
			if '%eax' in line.rsplit(',')[0] and '%esi' in line.rsplit(',')[1]:
				rep = str('8b 70') + stack.toHex(line.rsplit('0x')[1].rsplit('(')[0])
				shellcode = shellcode.replace(line,rep)
			if '%eax' in line.rsplit(',')[0] and '%ebx' in line.rsplit(',')[1]:
				rep = str('8b 58') + stack.toHex(line.rsplit('0x')[1].rsplit('(')[0])
				shellcode = shellcode.replace(line,rep)
			if '%ebx' in line.rsplit(',')[0] and '%edx' in line.rsplit(',')[1]:
				rep = str('8b 53') + stack.toHex(line.rsplit('0x')[1].rsplit('(')[0])
				shellcode = shellcode.replace(line,rep)
			if '%edx' in line.rsplit(',')[0] and '%edx' in line.rsplit(',')[1]:
				rep = str('8b 52') + stack.toHex(line.rsplit('0x')[1].rsplit('(')[0])
				shellcode = shellcode.replace(line,rep)
			if '%edx' in line.rsplit(',')[0] and '%esi' in line.rsplit(',')[1]:
				rep = str('8b 72') + stack.toHex(line.rsplit('0x')[1].rsplit('(')[0])
				shellcode = shellcode.replace(line,rep)

		if 'mov $0x' in line and len(line.rsplit('$0x')[1].rsplit(',')[0]) == 4:
			if '%cx' in line:
				if _version is 2:
					rep = str('66 b9') + stack.st(str(binascii.a2b_hex(line.rsplit('$0x')[1].rsplit(',')[0])))
				if _version is 3:
					rep = str('66 b9') + stack.st(str(binascii.a2b_hex(line.rsplit('$0x')[1].rsplit(',')[0].encode('latin-1')).decode('latin-1')))
				shellcode = shellcode.replace(line,rep)
			if '%dx' in line:
				if _version is 2:
					rep = str('66 ba') + stack.st(str(binascii.a2b_hex(line.rsplit('$0x')[1].rsplit(',')[0])))
				if _version is 3:
					rep = str('66 ba') + stack.st(str(binascii.a2b_hex(line.rsplit('$0x')[1].rsplit(',')[0].encode('latin-1')).decode('latin-1')))
				shellcode = shellcode.replace(line,rep)

		if 'add' in line:
			if '$0x' in line:
				if '%esp' in line.rsplit(',')[1]:
					if _version is 2:
						rep = str('83 c4') + stack.st(str(binascii.a2b_hex(stack.toHex(line.rsplit('$0x')[1].rsplit(',')[0]))))
					if _version is 3:
						rep = str('83 c4') + stack.st(str(binascii.a2b_hex(stack.toHex(line.rsplit('$0x')[1].rsplit(',')[0]).encode('latin-1')).decode('latin-1')))
					shellcode = shellcode.replace(line,rep)

		if 'cmpl' in line:
			if '(%eax)' == line.rsplit(',')[1]:
				if _version is 2:
					rep = str('81 38') + stack.st(str(binascii.a2b_hex(line.rsplit('$0x')[1].rsplit(',')[0])))
				if _version is 3:
					rep = str('81 38') + stack.st(str(binascii.a2b_hex(line.rsplit('$0x')[1].rsplit(',')[0].encode('latin-1')).decode('latin-1')))
				shellcode = shellcode.replace(line,rep)
			if '0x' in line.rsplit(',')[1]:
				if '%eax' in line:
					if _version is 2:
						rep = str('81 78') + stack.st(str(binascii.a2b_hex(stack.toHex(line.rsplit(',0x')[1].rsplit('(')[0])))) + stack.st(str(binascii.a2b_hex(line.rsplit('$0x')[1].rsplit(',')[0])))
					if _version is 3:
						rep = str('81 78') + stack.st(str(binascii.a2b_hex(stack.toHex(line.rsplit(',0x')[1].rsplit('(')[0]).encode('latin-1')).decode('latin-1'))) + stack.st(str(binascii.a2b_hex(line.rsplit('$0x')[1].rsplit(',')[0].encode('latin-1')).decode('latin-1')))
					shellcode = shellcode.replace(line,rep)

		if 'jne' in line:
			rep = str('75') + hex(int('f4', 16) - last*9)[2:]
			shellcode = shellcode.replace(line,rep,1)
			last += 1
	shellcode = stack.shellcoder(shellcode.replace('\n','').replace(' ',''))
	return shellcode


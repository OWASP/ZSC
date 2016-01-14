#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
def generator(shellcode,os):
	if os == 'linux_x86':
		from lib.opcoder import linux_x86
		shellcode = linux_x86.convert(shellcode)
	if os == 'linux_x64':
		from lib.opcoder import linux_x64
		shellcode = linux_x64.convert(shellcode)
	if os == 'linux_arm':
		from lib.opcoder import linux_arm
		shellcode = linux_arm.convert(shellcode)
	if os == 'linux_mips':
		from lib.opcoder import linux_mips
		shellcode = linux_mips.convert(shellcode)
	if os == 'freebsd_x86':
		from lib.opcoder import freebsd_x86
		shellcode = freebsd_x86.convert(shellcode)
	if os == 'freebsd_x64':
		from lib.opcoder import freebsd_x64
		shellcode = freebsd_x64.convert(shellcode)
	if os == 'windows_x86':
		from lib.opcoder import windows_x86
		shellcode = windows_x86.convert(shellcode)
	if os == 'windows_x64':
		from lib.opcoder import windows_x64
		shellcode = windows_x64.convert(shellcode)
	if os == 'osx':
		from lib.opcoder import osx
		shellcode = osx.convert(shellcode)
	if os == 'solaris_x86':
		from lib.opcoder import solaris_x86
		shellcode = solaris_x86.convert(shellcode)
	if os == 'solaris_x64':
		from lib.opcoder import solaris_x64
		shellcode = solaris_x64.convert(shellcode)
	return shellcode

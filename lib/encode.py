#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
def process(type,shellcode,os_name,job):
	if type == 'none':
		from encoder.none import start
		return start(shellcode)
	if 'freebsd_x64' in os_name:	
		if type == 'add_random':
			from encoder.freebsd_x64.add_random import start
			return start(shellcode,job)	
		if 'add_' in type:
			from encoder.freebsd_x64.add_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'dec':
			from encoder.freebsd_x64.dec import start
			return start(shellcode,job)	
		if 'dec_' in type:
			from encoder.freebsd_x64.dec_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'inc':
			from encoder.freebsd_x64.inc import start
			return start(shellcode,job)	
		if 'inc_' in type:
			from encoder.freebsd_x64.inc_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'mix_all':
			from encoder.freebsd_x64.mix_all import start
			return start(shellcode,job)	
		if type == 'sub_random':
			from encoder.freebsd_x64.sub_random import start
			return start(shellcode,job)	
		if 'sub_' in type:
			from encoder.freebsd_x64.sub_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'xor_random':
			from encoder.freebsd_x64.xor_random import start
			return start(shellcode,job)
		if 'xor_' in type:
			from encoder.freebsd_x64.xor_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode	
	if 'freebsd_x86' in os_name:	
		if type == 'add_random':
			from encoder.freebsd_x86.add_random import start
			return start(shellcode,job)	
		if 'add_' in type:
			from encoder.freebsd_x86.add_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'dec':
			from encoder.freebsd_x86.dec import start
			return start(shellcode,job)	
		if 'dec_' in type:
			from encoder.freebsd_x86.dec_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'inc':
			from encoder.freebsd_x86.inc import start
			return start(shellcode,job)	
		if 'inc_' in type:
			from encoder.freebsd_x86.inc_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'mix_all':
			from encoder.freebsd_x86.mix_all import start
			return start(shellcode,job)	
		if type == 'sub_random':
			from encoder.freebsd_x86.sub_random import start
			return start(shellcode,job)	
		if 'sub_' in type:
			from encoder.freebsd_x86.sub_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'xor_random':
			from encoder.freebsd_x86.xor_random import start
			return start(shellcode,job)
		if 'xor_' in type:
			from encoder.freebsd_x86.xor_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode	
	if 'linux_arm' in os_name:	
		if type == 'add_random':
			from encoder.linux_arm.add_random import start
			return start(shellcode,job)	
		if 'add_' in type:
			from encoder.linux_arm.add_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'dec':
			from encoder.linux_arm.dec import start
			return start(shellcode,job)	
		if 'dec_' in type:
			from encoder.linux_arm.dec_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'inc':
			from encoder.linux_arm.inc import start
			return start(shellcode,job)	
		if 'inc_' in type:
			from encoder.linux_arm.inc_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'mix_all':
			from encoder.linux_arm.mix_all import start
			return start(shellcode,job)	
		if type == 'sub_random':
			from encoder.linux_arm.sub_random import start
			return start(shellcode,job)	
		if 'sub_' in type:
			from encoder.linux_arm.sub_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'xor_random':
			from encoder.linux_arm.xor_random import start
			return start(shellcode,job)
		if 'xor_' in type:
			from encoder.linux_arm.xor_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode	
	if 'linux_mips' in os_name:	
		if type == 'add_random':
			from encoder.linux_mips.add_random import start
			return start(shellcode,job)	
		if 'add_' in type:
			from encoder.linux_mips.add_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'dec':
			from encoder.linux_mips.dec import start
			return start(shellcode,job)	
		if 'dec_' in type:
			from encoder.linux_mips.dec_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'inc':
			from encoder.linux_mips.inc import start
			return start(shellcode,job)	
		if 'inc_' in type:
			from encoder.linux_mips.inc_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'mix_all':
			from encoder.linux_mips.mix_all import start
			return start(shellcode,job)	
		if type == 'sub_random':
			from encoder.linux_mips.sub_random import start
			return start(shellcode,job)	
		if 'sub_' in type:
			from encoder.linux_mips.sub_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'xor_random':
			from encoder.linux_mips.xor_random import start
			return start(shellcode,job)
		if 'xor_' in type:
			from encoder.linux_mips.xor_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode		
	if 'linux_x64' in os_name:	
		if type == 'add_random':
			from encoder.linux_x64.add_random import start
			return start(shellcode,job)	
		if 'add_' in type:
			from encoder.linux_x64.add_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'dec':
			from encoder.linux_x64.dec import start
			return start(shellcode,job)	
		if 'dec_' in type:
			from encoder.linux_x64.dec_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'inc':
			from encoder.linux_x64.inc import start
			return start(shellcode,job)	
		if 'inc_' in type:
			from encoder.linux_x64.inc_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'mix_all':
			from encoder.linux_x64.mix_all import start
			return start(shellcode,job)	
		if type == 'sub_random':
			from encoder.linux_x64.sub_random import start
			return start(shellcode,job)	
		if 'sub_' in type:
			from encoder.linux_x64.sub_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'xor_random':
			from encoder.linux_x64.xor_random import start
			return start(shellcode,job)
		if 'xor_' in type:
			from encoder.linux_x64.xor_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode	
	if 'linux_x86' in os_name:	
		if type == 'add_random':
			from encoder.linux_x86.add_random import start
			return start(shellcode,job)	
		if 'add_' in type:
			from encoder.linux_x86.add_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'dec':
			from encoder.linux_x86.dec import start
			return start(shellcode,job)	
		if 'dec_' in type:
			from encoder.linux_x86.dec_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'inc':
			from encoder.linux_x86.inc import start
			return start(shellcode,job)	
		if 'inc_' in type:
			from encoder.linux_x86.inc_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'mix_all':
			from encoder.linux_x86.mix_all import start
			return start(shellcode,job)	
		if type == 'sub_random':
			from encoder.linux_x86.sub_random import start
			return start(shellcode,job)	
		if 'sub_' in type:
			from encoder.linux_x86.sub_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'xor_random':
			from encoder.linux_x86.xor_random import start
			return start(shellcode,job)
		if 'xor_' in type:
			from encoder.linux_x86.xor_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode	
			
	if 'solaris_x64' in os_name:	
		if type == 'add_random':
			from encoder.solaris_x64.add_random import start
			return start(shellcode,job)	
		if 'add_' in type:
			from encoder.solaris_x64.add_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'dec':
			from encoder.solaris_x64.dec import start
			return start(shellcode,job)	
		if 'dec_' in type:
			from encoder.solaris_x64.dec_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'inc':
			from encoder.solaris_x64.inc import start
			return start(shellcode,job)	
		if 'inc_' in type:
			from encoder.solaris_x64.inc_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'mix_all':
			from encoder.solaris_x64.mix_all import start
			return start(shellcode,job)	
		if type == 'sub_random':
			from encoder.solaris_x64.sub_random import start
			return start(shellcode,job)	
		if 'sub_' in type:
			from encoder.solaris_x64.sub_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'xor_random':
			from encoder.solaris_x64.xor_random import start
			return start(shellcode,job)
		if 'xor_' in type:
			from encoder.solaris_x64.xor_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode	
			
	if 'solaris_x86' in os_name:	
		if type == 'add_random':
			from encoder.solaris_x86.add_random import start
			return start(shellcode,job)	
		if 'add_' in type:
			from encoder.solaris_x86.add_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'dec':
			from encoder.solaris_x86.dec import start
			return start(shellcode,job)	
		if 'dec_' in type:
			from encoder.solaris_x86.dec_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'inc':
			from encoder.solaris_x86.inc import start
			return start(shellcode,job)	
		if 'inc_' in type:
			from encoder.solaris_x86.inc_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'mix_all':
			from encoder.solaris_x86.mix_all import start
			return start(shellcode,job)	
		if type == 'sub_random':
			from encoder.solaris_x86.sub_random import start
			return start(shellcode,job)	
		if 'sub_' in type:
			from encoder.solaris_x86.sub_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'xor_random':
			from encoder.solaris_x86.xor_random import start
			return start(shellcode,job)
		if 'xor_' in type:
			from encoder.solaris_x86.xor_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode	
			
	if 'windows_x64' in os_name:	
		if type == 'add_random':
			from encoder.windows_x64.add_random import start
			return start(shellcode,job)	
		if 'add_' in type:
			from encoder.windows_x64.add_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'dec':
			from encoder.windows_x64.dec import start
			return start(shellcode,job)	
		if 'dec_' in type:
			from encoder.windows_x64.dec_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'inc':
			from encoder.windows_x64.inc import start
			return start(shellcode,job)	
		if 'inc_' in type:
			from encoder.windows_x64.inc_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'mix_all':
			from encoder.windows_x64.mix_all import start
			return start(shellcode,job)	
		if type == 'sub_random':
			from encoder.windows_x64.sub_random import start
			return start(shellcode,job)	
		if 'sub_' in type:
			from encoder.windows_x64.sub_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'xor_random':
			from encoder.windows_x64.xor_random import start
			return start(shellcode,job)
		if 'xor_' in type:
			from encoder.windows_x64.xor_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode	
			
	if 'windows_x86' in os_name:	
		if type == 'add_random':
			from encoder.windows_x86.add_random import start
			return start(shellcode,job)	
		if 'add_' in type:
			from encoder.windows_x86.add_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'dec':
			from encoder.windows_x86.dec import start
			return start(shellcode,job)	
		if 'dec_' in type:
			from encoder.windows_x86.dec_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'inc':
			from encoder.windows_x86.inc import start
			return start(shellcode,job)	
		if 'inc_' in type:
			from encoder.windows_x86.inc_timesyouwant import start
			shellcode = start(type,shellcode,job)
			return shellcode	
		if type == 'mix_all':
			from encoder.windows_x86.mix_all import start
			return start(shellcode,job)	
		if type == 'sub_random':
			from encoder.windows_x86.sub_random import start
			return start(shellcode,job)	
		if 'sub_' in type:
			from encoder.windows_x86.sub_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode
		if type == 'xor_random':
			from encoder.windows_x86.xor_random import start
			return start(shellcode,job)
		if 'xor_' in type:
			from encoder.windows_x86.xor_yourvalue import start
			shellcode = start(type,shellcode,job)
			return shellcode	

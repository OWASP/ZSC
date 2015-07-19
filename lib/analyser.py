#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
import encode
import sys
from core import color
def chmod_spliter(cont):
	cont = cont.replace('chmod(\'','')
	cont = cont.replace('\',\'','\x90\x90\x90')
	cont = cont.replace('\')','')
	cont = cont.rsplit('\x90\x90\x90')
	return cont[0] + '\x90\x90\x90' + cont[1]
def dir_creator(cont):
	cont = cont.replace('dir_create(\'','')
	cont = cont.replace('\',\'','')
	cont = cont.replace('\')','')
	return cont
def download_spliter(cont):
	cont = cont.replace('download(\'','')
	cont = cont.replace('\',\'','\x90\x90\x90')
	cont = cont.replace('\')','')
	cont = cont.rsplit('\x90\x90\x90')
	return cont[0] + '\x90\x90\x90' + cont[1]
def download_exec_spliter(cont):
	cont = cont.replace('download_execute(\'','')
	cont = cont.replace('\',\'','\x90\x90\x90')
	cont = cont.replace('\')','')
	cont = cont.rsplit('\x90\x90\x90')
	return cont[0] + '\x90\x90\x90' + cont[1]+ '\x90\x90\x90' + cont[2]
def executor(cont):
	cont = cont.replace('exec(\'','')
	cont = cont.replace('\',\'','')
	cont = cont.replace('\')','')
	return cont
def file_creator(cont):
	cont = cont.replace('file_create(\'','')
	cont = cont.replace('\',\'','\x90\x90\x90')
	cont = cont.replace('\')','')
	cont = cont.rsplit('\x90\x90\x90')
	return cont[0] + '\x90\x90\x90' + cont[1]
def script_exec(cont):
	cont = cont.replace('script_executor(\'','')
	cont = cont.replace('\',\'','\x90\x90\x90')
	cont = cont.replace('\')','')
	cont = cont.rsplit('\x90\x90\x90')
	return cont[0] + '\x90\x90\x90' + cont[1]+ '\x90\x90\x90' + cont[2]
def syst(cont):
	cont = cont.replace('system(\'','')
	cont = cont.replace('\',\'','')
	cont = cont.replace('\')','')
	return cont
def file_writer(cont):
	cont = cont.replace('write(\'','')
	cont = cont.replace('\',\'','\x90\x90\x90')
	cont = cont.replace('\')','')
	cont = cont.rsplit('\x90\x90\x90')
	return cont[0] + '\x90\x90\x90' + cont[1]
def do(cont):
	content = cont.rsplit('\x90\x90\x90')
	os_name,filename,encode_type,job = content[0],content[1],content[2],content[3]
	shellcode = None
	if 'freebsd_x64' in os_name:
		if 'chmod(' in job:
			from generator.freebsd_x64 import chmod
			values = chmod_spliter(job).rsplit('\x90\x90\x90')
			shellcode = chmod.run(values[0],values[1])
		if 'dir_create(' in job:
			from generator.freebsd_x64 import dir_create
			shellcode = dir_create.run(dir_creator(job))
		if 'download(' in job:
			from generator.freebsd_x64 import download
			values = download_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download.run(values[0],values[1])
		if 'download_execute(' in job:
			from generator.freebsd_x64 import download_execute
			values = download_exec_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download_execute.run(values[0],values[1],values[2])
		if 'exec(' in job:
			from generator.freebsd_x64 import exc
			shellcode = exc.run(executor(job))
		if 'file_create(' in job:
			from generator.freebsd_x64 import file_create
			values = file_creator(job).rsplit('\x90\x90\x90')
			shellcode = file_create.run(values[0],values[1])
		if 'script_executor(' in job:
			from generator.freebsd_x64 import script_executor
			values = script_exec(job).rsplit('\x90\x90\x90')
			shellcode = script_executor.run(values[0],values[1],values[2])
		if 'system(' in job:
			from generator.freebsd_x64 import system
			shellcode = system.run(syst(job))
		if 'write(' in job: 
			from generator.freebsd_x64 import write
			values = file_writer(job).rsplit('\x90\x90\x90')
			shellcode = write.run(values[0],values[1])
	if 'freebsd_x86' in os_name:
		if 'chmod(' in job:
			from generator.freebsd_x86 import chmod
			values = chmod_spliter(job).rsplit('\x90\x90\x90')
			shellcode = chmod.run(values[0],values[1])
		if 'dir_create(' in job:
			from generator.freebsd_x86 import dir_create
			value = dir_creator(job)
			shellcode = dir_create.run(value)
		if 'download(' in job:
			from generator.freebsd_x86 import download
			values = download_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download.run(values[0],values[1])
		if 'download_execute(' in job:
			from generator.freebsd_x86 import download_execute
			values = download_exec_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download_execute.run(values[0],values[1],values[2])
		if 'exec(' in job:
			from generator.freebsd_x86 import exc
			shellcode = exc.run(executor(job))
		if 'file_create(' in job:
			from generator.freebsd_x86 import file_create
			values = file_creator(job).rsplit('\x90\x90\x90')
			shellcode = file_create.run(values[0],values[1])
		if 'script_executor(' in job:
			from generator.freebsd_x86 import script_executor
			values = script_exec(job).rsplit('\x90\x90\x90')
			shellcode = script_executor.run(values[0],values[1],values[2])
		if 'system(' in job:
			from generator.freebsd_x86 import system
			shellcode = system.run(syst(job))
		if 'write(' in job: 
			from generator.freebsd_x86 import write
			values = file_writer(job).rsplit('\x90\x90\x90')
			shellcode = write.run(values[0],values[1])
	if 'linux_arm' in os_name: 
		if 'chmod(' in job:
			from generator.linux_arm import chmod
			values = chmod_spliter(job).rsplit('\x90\x90\x90')
			shellcode = chmod.run(values[0],values[1])
		if 'dir_create(' in job:
			from generator.linux_arm import dir_create
			value = dir_creator(job)
			shellcode = dir_create.run(value)
		if 'download(' in job:
			from generator.linux_arm import download
			values = download_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download.run(values[0],values[1])
		if 'download_execute(' in job:
			from generator.linux_arm import download_execute
			values = download_exec_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download_execute.run(values[0],values[1],values[2])
		if 'exec(' in job:
			from generator.linux_arm import exc
			shellcode = exc.run(executor(job))
		if 'file_create(' in job:
			from generator.linux_arm import file_create
			values = file_creator(job).rsplit('\x90\x90\x90')
			shellcode = file_create.run(values[0],values[1])
		if 'script_executor(' in job:
			from generator.linux_arm import script_executor
			values = script_exec(job).rsplit('\x90\x90\x90')
			shellcode = script_executor.run(values[0],values[1],values[2])
		if 'system(' in job:
			from generator.linux_arm import system
			shellcode = system.run(syst(job))
		if 'write(' in job: 
			from generator.linux_arm import write
			values = file_writer(job).rsplit('\x90\x90\x90')
			shellcode = write.run(values[0],values[1])
	if 'linux_mips' in os_name:
		if 'chmod(' in job:
			from generator.linux_mips import chmod
			values = chmod_spliter(job).rsplit('\x90\x90\x90')
			shellcode = chmod.run(values[0],values[1])
		if 'dir_create(' in job:
			from generator.linux_mips import dir_create
			value = dir_creator(job)
			shellcode = dir_create.run(value)
		if 'download(' in job:
			from generator.linux_mips import download
			values = download_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download.run(values[0],values[1])
		if 'download_execute(' in job:
			from generator.linux_mips import download_execute
			values = download_exec_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download_execute.run(values[0],values[1],values[2])
		if 'exec(' in job:
			from generator.linux_mips import exc
			shellcode = exc.run(executor(job))
		if 'file_create(' in job:
			from generator.linux_mips import file_create
			values = file_creator(job).rsplit('\x90\x90\x90')
			shellcode = file_create.run(values[0],values[1])
		if 'script_executor(' in job:
			from generator.linux_mips import script_executor
			values = script_exec(job).rsplit('\x90\x90\x90')
			shellcode = script_executor.run(values[0],values[1],values[2])
		if 'system(' in job:
			from generator.linux_mips import system
			shellcode = system.run(syst(job))
		if 'write(' in job: 
			from generator.linux_mips import write
			values = file_writer(job).rsplit('\x90\x90\x90')
			shellcode = write.run(values[0],values[1])
	if 'linux_x64' in os_name:
		if 'chmod(' in job:
			from generator.linux_x64 import chmod
			values = chmod_spliter(job).rsplit('\x90\x90\x90')
			shellcode = chmod.run(values[0],values[1])
		if 'dir_create(' in job:
			from generator.linux_x64 import dir_create
			value = dir_creator(job)
			shellcode = dir_create.run(value)
		if 'download(' in job:
			from generator.linux_x64 import download
			values = download_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download.run(values[0],values[1])
		if 'download_execute(' in job:
			from generator.linux_x64 import download_execute
			values = download_exec_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download_execute.run(values[0],values[1],values[2])
		if 'exec(' in job:
			from generator.linux_x64 import exc
			shellcode = exc.run(executor(job))
		if 'file_create(' in job:
			from generator.linux_x64 import file_create
			values = file_creator(job).rsplit('\x90\x90\x90')
			shellcode = file_create.run(values[0],values[1])
		if 'script_executor(' in job:
			from generator.linux_x64 import script_executor
			values = script_exec(job).rsplit('\x90\x90\x90')
			shellcode = script_executor.run(values[0],values[1],values[2])
		if 'system(' in job:
			from generator.linux_x64 import system
			shellcode = system.run(syst(job))
		if 'write(' in job: 
			from generator.linux_x64 import write
			values = file_writer(job).rsplit('\x90\x90\x90')
			shellcode = write.run(values[0],values[1])
	if 'linux_x86' in os_name:
		if 'chmod(' in job:
			from generator.linux_x86 import chmod
			values = chmod_spliter(job).rsplit('\x90\x90\x90')
			shellcode = chmod.run(values[0],values[1])
		if 'dir_create(' in job:
			from generator.linux_x86 import dir_create
			value = dir_creator(job)
			shellcode = dir_create.run(value)
		if 'download(' in job:
			from generator.linux_x86 import download
			values = download_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download.run(values[0],values[1])
		if 'download_execute(' in job:
			from generator.linux_x86 import download_execute
			values = download_exec_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download_execute.run(values[0],values[1],values[2])
		if 'exec(' in job:
			from generator.linux_x86 import exc
			shellcode = exc.run(executor(job))
		if 'file_create(' in job:
			from generator.linux_x86 import file_create
			values = file_creator(job).rsplit('\x90\x90\x90')
			shellcode = file_create.run(values[0],values[1])
		if 'script_executor(' in job:
			from generator.linux_x86 import script_executor
			values = script_exec(job).rsplit('\x90\x90\x90')
			shellcode = script_executor.run(values[0],values[1],values[2])
		if 'system(' in job:
			from generator.linux_x86 import system
			shellcode = system.run(syst(job))
		if 'write(' in job: 
			from generator.linux_x86 import write
			values = file_writer(job).rsplit('\x90\x90\x90')
			shellcode = write.run(values[0],values[1])
	if 'osx' in os_name:
		if 'chmod(' in job:
			from generator.osx import chmod
			values = chmod_spliter(job).rsplit('\x90\x90\x90')
			shellcode = chmod.run(values[0],values[1])
		if 'dir_create(' in job:
			from generator.osx import dir_create
			value = dir_creator(job)
			shellcode = dir_create.run(value)
		if 'download(' in job:
			from generator.osx import download
			values = download_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download.run(values[0],values[1])
		if 'download_execute(' in job:
			from generator.osx import download_execute
			values = download_exec_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download_execute.run(values[0],values[1],values[2])
		if 'exec(' in job:
			from generator.osx import exc
			shellcode = exc.run(executor(job))
		if 'file_create(' in job:
			from generator.osx import file_create
			values = file_creator(job).rsplit('\x90\x90\x90')
			shellcode = file_create.run(values[0],values[1])
		if 'script_executor(' in job:
			from generator.osx import script_executor
			values = script_exec(job).rsplit('\x90\x90\x90')
			shellcode = script_executor.run(values[0],values[1],values[2])
		if 'system(' in job:
			from generator.osx import system
			shellcode = system.run(syst(job))
		if 'write(' in job: 
			from generator.osx import write
			values = file_writer(job).rsplit('\x90\x90\x90')
			shellcode = write.run(values[0],values[1])
	if 'solaris_x64' in os_name:
		if 'chmod(' in job:
			from generator.solaris_x64 import chmod
			values = chmod_spliter(job).rsplit('\x90\x90\x90')
			shellcode = chmod.run(values[0],values[1])
		if 'dir_create(' in job:
			from generator.solaris_x64 import dir_create
			value = dir_creator(job)
			shellcode = dir_create.run(value)
		if 'download(' in job:
			from generator.solaris_x64 import download
			values = download_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download.run(values[0],values[1])
		if 'download_execute(' in job:
			from generator.solaris_x64 import download_execute
			values = download_exec_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download_execute.run(values[0],values[1],values[2])
		if 'exec(' in job:
			from generator.solaris_x64 import exc
			shellcode = exc.run(executor(job))
		if 'file_create(' in job:
			from generator.solaris_x64 import file_create
			values = file_creator(job).rsplit('\x90\x90\x90')
			shellcode = file_create.run(values[0],values[1])
		if 'script_executor(' in job:
			from generator.solaris_x64 import script_executor
			values = script_exec(job).rsplit('\x90\x90\x90')
			shellcode = script_executor.run(values[0],values[1],values[2])
		if 'system(' in job:
			from generator.solaris_x64 import system
			shellcode = system.run(syst(job))
		if 'write(' in job: 
			from generator.solaris_x64 import write
			values = file_writer(job).rsplit('\x90\x90\x90')
			shellcode = write.run(values[0],values[1])
	if 'solaris_x86' in os_name:
		if 'chmod(' in job:
			from generator.solaris_x86 import chmod
			values = chmod_spliter(job).rsplit('\x90\x90\x90')
			shellcode = chmod.run(values[0],values[1])
		if 'dir_create(' in job:
			from generator.solaris_x86 import dir_create
			value = dir_creator(job)
			shellcode = dir_create.run(value)
		if 'download(' in job:
			from generator.solaris_x86 import download
			values = download_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download.run(values[0],values[1])
		if 'download_execute(' in job:
			from generator.solaris_x86 import download_execute
			values = download_exec_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download_execute.run(values[0],values[1],values[2])
		if 'exec(' in job:
			from generator.solaris_x86 import exc
			shellcode = exc.run(executor(job))
		if 'file_create(' in job:
			from generator.solaris_x86 import file_create
			values = file_creator(job).rsplit('\x90\x90\x90')
			shellcode = file_create.run(values[0],values[1])
		if 'script_executor(' in job:
			from generator.solaris_x86 import script_executor
			values = script_exec(job).rsplit('\x90\x90\x90')
			shellcode = script_executor.run(values[0],values[1],values[2])
		if 'system(' in job:
			from generator.solaris_x86 import system
			shellcode = system.run(syst(job))
		if 'write(' in job: 
			from generator.solaris_x86 import write
			values = file_writer(job).rsplit('\x90\x90\x90')
			shellcode = write.run(values[0],values[1])
	if 'windows_x64' in os_name:
		if 'chmod(' in job:
			from generator.windows_x64 import chmod
			values = chmod_spliter(job).rsplit('\x90\x90\x90')
			shellcode = chmod.run(values[0],values[1])
		if 'dir_create(' in job:
			from generator.windows_x64 import dir_create
			value = dir_creator(job)
			shellcode = dir_create.run(value)
		if 'download(' in job:
			from generator.windows_x64 import download
			values = download_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download.run(values[0],values[1])
		if 'download_execute(' in job:
			from generator.windows_x64 import download_execute
			values = download_exec_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download_execute.run(values[0],values[1],values[2])
		if 'exec(' in job:
			from generator.windows_x64 import exc
			shellcode = exc.run(executor(job))
		if 'file_create(' in job:
			from generator.windows_x64 import file_create
			values = file_creator(job).rsplit('\x90\x90\x90')
			shellcode = file_create.run(values[0],values[1])
		if 'script_executor(' in job:
			from generator.windows_x64 import script_executor
			values = script_exec(job).rsplit('\x90\x90\x90')
			shellcode = script_executor.run(values[0],values[1],values[2])
		if 'system(' in job:
			from generator.windows_x64 import system
			shellcode = system.run(syst(job))
		if 'write(' in job: 
			from generator.windows_x64 import write
			values = file_writer(job).rsplit('\x90\x90\x90')
			shellcode = write.run(values[0],values[1])
	if 'windows_x86' in os_name:
		if 'chmod(' in job:
			from generator.windows_x86 import chmod
			values = chmod_spliter(job).rsplit('\x90\x90\x90')
			shellcode = chmod.run(values[0],values[1])
		if 'dir_create(' in job:
			from generator.windows_x86 import dir_create
			value = dir_creator(job)
			shellcode = dir_create.run(value)
		if 'download(' in job:
			from generator.windows_x86 import download
			values = download_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download.run(values[0],values[1])
		if 'download_execute(' in job:
			from generator.windows_x86 import download_execute
			values = download_exec_spliter(job).rsplit('\x90\x90\x90')
			shellcode = download_execute.run(values[0],values[1],values[2])
		if 'exec(' in job:
			from generator.windows_x86 import exc
			shellcode = exc.run(executor(job))
		if 'file_create(' in job:
			from generator.windows_x86 import file_create
			values = file_creator(job).rsplit('\x90\x90\x90')
			shellcode = file_create.run(values[0],values[1])
		if 'script_executor(' in job:
			from generator.windows_x86 import script_executor
			values = script_exec(job).rsplit('\x90\x90\x90')
			shellcode = script_executor.run(values[0],values[1],values[2])
		if 'system(' in job:
			from generator.windows_x86 import system
			shellcode = system.run(syst(job))
		if 'write(' in job: 
			from generator.windows_x86 import write
			values = file_writer(job).rsplit('\x90\x90\x90')
			shellcode = write.run(values[0],values[1])
	if shellcode is not None:
		shellcode = encode.process(encode_type,shellcode,os_name,job).replace('\n\n','\n').replace('\n\n','\n')
	save = open('output/'+filename,'w')
	save.write(shellcode)
	save.close()
	color.color(10)
	sys.stdout.write('Your Shellcode file generated!\n')
	color.color(11)
	sys.stdout.write('\nOS: ')
	color.color(12)
	sys.stdout.write(os_name)
	color.color(11)
	sys.stdout.write('\nOutput: ')
	color.color(12)
	sys.stdout.write('output/'+filename)
	color.color(11)
	sys.stdout.write('\nEncode: ')
	color.color(12)
	sys.stdout.write(encode_type)
	color.color(11)
	sys.stdout.write('\nJob: ')
	color.color(12)
	sys.stdout.write(job+'\n\n')
#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
import os
import sys
from core import start
from core import color
#start.logo()
def check_prv():
	try:
		if os.geteuid() is not 0:
			sys.exit(color.color('red')+'Sorry, you most run this file as root.'+color.color('reset'))
	except AttributeError:
		import ctypes
		if ctypes.windll.shell32.IsUserAnAdmin() != 1:
			sys.exit(color.color('red')+'Sorry, you most run this file as admin.'+color.color('reset'))
def linux_osx():
	check_prv()
	executor = '''#!/bin/bash\npython /usr/share/owasp_zsc/zsc.py "$@"'''
	print (color.color('cyan')+'Building Commandline')
	commandline = open('/usr/bin/zsc','w')
	commandline.write(executor)
	commandline.close()
	print (color.color('green')+'Copying Files'+color.color('white'))
	os.system('rm -rf /usr/share/owasp_zsc && mkdir /usr/share/owasp_zsc && cp -r * /usr/share/owasp_zsc/ && chmod +x /usr/share/owasp_zsc/zsc.py && chmod +x /usr/bin/zsc')
	print (color.color('yellow') + '\nNow you can remove this folder\nfiles copied in /usr/share/owasp_zsc.\nto run zcr shellcoder please use "zsc" command line\n'+color.color('reset'))
def windows():
	#check_prv()
	installing_path = str(sys.prefix) + str('\\Scripts\\zsc')
	try:
		os.mkdir(installing_path)
	except:
		pass
	print (color.color('green')+'Copying Files'+color.color('white'))
	tmp_copy = os.popen('xcopy /y /s /i . %s'%installing_path).read()
	print (color.color('cyan')+'Building Commandline')
	tmp_add_command_line = open('%s\\..\\zsc.bat'%installing_path,'w')
	tmp_add_command_line.write('@echo off\npython %s\\zsc.py'%installing_path)
	tmp_add_command_line.close()
	print (color.color('yellow') + '\nNow you can remove this folder\nfiles copied in %s.\nto run zcr shellcoder please use "zsc" command line\nNOTE: IF COMMAND LINE "zsc" NOT FOUND, PLEASE RE-OPEN YOUR CMD!\N'%installing_path+color.color('reset'))
if 'linux' in sys.platform or 'darwin' in sys.platform:
	os.system('clear')
	linux_osx()
elif 'win32' in sys.platform or 'win64' in sys.platform:
	os.system('cls')
	windows()
else:
	sys.exit(color.color('red')+'OWASP ZSC currently supports install on windows/linux/osx only, for other platforms please copy source files to a directory and run'+color.color('reset'))
start.sig()

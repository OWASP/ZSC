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
if 'linux' in sys.platform or 'darwin' in sys.platform:
	if os.geteuid() is not 0:
		sys.exit(color.color('red')+'Sorry, you most run this file as root.'+color.color('reset'))
	os.system('clear')
	print (color.color('green')+'Removing Files'+color.color('white'))
	os.system('rm -rf /usr/share/owasp_zsc /usr/bin/zsc')
	print (color.color('green')+'Files Removed!'+color.color('white'))
elif 'win32' in sys.platform or 'win64' in sys.platform:
	#import ctypes
	#if ctypes.windll.shell32.IsUserAnAdmin() != 1:
	#	sys.exit(color.color('red')+'Sorry, you most run this file as admin.'+color.color('reset'))
	print (color.color('green')+'Removing Files'+color.color('white'))
	installing_path = str(sys.prefix) + str('\\Scripts\\zsc')
	os.system('rmdir %s /s /q'%installing_path)
	os.system('del %s\\..\\zsc.bat /f'%installing_path)
	print (color.color('green')+'Files Removed!'+color.color('white'))
else:
	sys.exit(color.color('red')+'OWASP ZSC currently supports uninstall on windows/linux/osx only, for other platforms please remove source files.'+color.color('reset'))
start.sig()

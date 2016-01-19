#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
import os
import sys
from core import start
from core import color
if 'linux' in sys.platform or 'darwin' in sys.platform:
	os.system('clear')
else:
	sys.exit(color.color('red')+'Sorry, This version of software just could be INSTALL on linux/osx.'+color.color('reset'))
if os.geteuid() is not 0:
	sys.exit(color.color('red')+'Sorry, you most run this file as root.'+color.color('reset'))
start.logo()
executor = '''#!/bin/bash\npython /usr/share/owasp_zsc/zsc.py "$@"'''
print (color.color('cyan')+'Building Commandline')
commandline = open('/usr/bin/zsc','w')
commandline.write(executor)
commandline.close()
print (color.color('green')+'Copying Files'+color.color('white'))
os.system('rm -rf /usr/share/owasp_zsc && mkdir /usr/share/owasp_zsc && cp -r * /usr/share/owasp_zsc/ && chmod +x /usr/share/owasp_zsc/zsc.py && chmod +x /usr/bin/zsc')
print (color.color('yellow') + '\nNow you can remove this folder\nfiles copied in /usr/share/owasp_zsc.\nto run zcr shellcoder please use "zsc" command line\n'+color.color('reset'))
start.sig()

#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
import sys
#from core import update as upd
from core.compatible import version
__version__ = '1.0.9'
__key__ = 'Reboot'
__release_date__ = '2016 January 19'
from core import color
def logo():
	print (color.color('red') + '''
   ______          __      _____ _____    ___________ _____               
  / __ \ \        / /\    / ____|  __ \  |___  / ____|  __ \              
 | |  | \ \  /\  / /  \  | (___ | |__) |    / / |    | |__) |             
 | |  | |\ \/  \/ / /\ \  \___ \|  ___/    / /| |    |  _  /              
 | |__| | \  /\  / ____ \ ____) | |       / /_| |____| | \ \              
  \____/ _ \/ _\/_/___ \_\_____/|_|  ____/_____\_____|_|__\_\_ _____    _ 
  / ____| |  | |  ____| |    | |    / ____/ __ \|  __ \|  ____|  __ \  | |
 | (___ | |__| | |__  | |    | |   | |   | |  | | |  | | |__  | |__) | | |
  \___ \|  __  |  __| | |    | |   | |   | |  | | |  | |  __| |  _  /  | |
  ____) | |  | | |____| |____| |___| |___| |__| | |__| | |____| | \ \  |_|
 |_____/|_|  |_|______|______|______\_____\____/|_____/|______|_|  \_\ (_)
                                                                          
                                                                          
''' + color.color('cyan') + '\t\t\t'+color.color('green')+'OWASP' + color.color('cyan') + ' ZeroDay Cyber Research Shellcoder\n' + color.color('reset'))
def sig():
	print ('''%s
|----------------------------------------------------------------------------|
|%sVisit%s https://www.%sowasp%s.org/index.php/OWASP_ZSC_Tool_Project ---------------|
|----------------------------------------------------------------------------|%s'''%(color.color('blue'),color.color('red'),color.color('blue'),color.color('red'),color.color('blue'),color.color('reset')))
def inputcheck():
	print (color.color('yellow')+'''
[+] Wrong input, Check Help Menu ,Execute: zsc ''' + color.color('red') + '-h'+ '\n' + color.color('reset'))
	sys.exit(sig())
def about():
	write('\n')
	info = [['Code','https://github.com/Ali-Razmjoo/OWASP-ZSC'],['Contributors','https://github.com/Ali-Razmjoo/OWASP-ZSC/graphs/contributors'],['API','http://api.z3r0d4y.com/'],['Home','http://zsc.z3r0d4y.com/'],['Mailing List','https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project'],['Contact US Now','owasp-zsc-tool-project[at]lists[dot]owasp[dot]org']]
	for section in info:
		write('%s%s%s: %s%s%s\n'%(color.color('red'),section[0],color.color('reset'),color.color('yellow'),section[1],color.color('reset')))
	sig()
def _version():
	write('\n')
	write ('%sOWASP ZSC Version: %s%s\n'%(color.color('cyan'),color.color('red'),__version__))
	write ('%sKey: %s%s\n'%(color.color('cyan'),color.color('red'),__key__))
	write ('%sRelease Date: %s%s\n'%(color.color('cyan'),color.color('red'),__release_date__))
	sig()
#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
from core.alert import *
from core.compatible import version
def obf_code(lang,encode,filename,content):
	if version() is 3:
		content = content.decode('utf-8')
	start = getattr(__import__('lib.encoder.%s.%s'%(lang,encode), fromlist=['start']), 'start') #import endoing module
	content = start(content) #encoded content as returned value	
	if version() is 3:
		content = bytes(content, 'utf-8')
	f = open(filename,'wb') #writing content
	f.write(content)
	f.close()
	info('file "%s" encoded successfully!\n'%filename)
	return 
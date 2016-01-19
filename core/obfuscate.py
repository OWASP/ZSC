#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
def obf_code(lang,encode,filename,content):
	if lang == 'javascript':#add lang
		start = getattr(__import__('lib.encoder.%s.%s'%(lang,encode), fromlist=['start']), 'start')
		return start(filename,content)
	#add other languages  in here
	return 
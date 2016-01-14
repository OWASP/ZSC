#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
from core.pyversion import version
version = version()
from core import color
if version is 2:
	from urllib import urlopen
if version is 3:
	from urllib.request import urlopen
def startu(__version__):
	url = 'https://raw.githubusercontent.com/Ali-Razmjoo/ZCR-Shellcoder-Archive/master/last_version'
	up_url = 'https://raw.githubusercontent.com/Ali-Razmjoo/ZCR-Shellcoder-Archive/master/'
	err = 0 
	try:
		last_version = urlopen(url).read()
		last_version = last_version.rsplit()[0]
	except:
		print ('%sConnection Error!%s\n\n'%(color.color('red'),color.color('reset')))
		err = 1
	if err is 0:
		update = True
		if str(last_version) == str(__version__):
			print ('%syou are using the last version of software : %s%s%s'%(color.color('green'),color.color('red'),last_version,color.color('reset')))
			update = False
		if update is True:
			print ('%syour software version: %s%s%s\nlast version released: %s%s%s\n\nDownloading %szcr_shellcoder_%s%s%s.zip%s\n\n\n'%(color.color('green'),color.color('cyan'),str(__version__),color.color('green'),color.color('red'),str(last_version),color.color('green'),color.color('yellow'),color.color('red'),str(last_version),color.color('yellow'),color.color('reset')))
			up_url = up_url + 'zcr_shellcoder_%s.zip'%(last_version)
			try:
				file_name = up_url.split('/')[-1]
				u = urlopen(up_url)
				f = open(file_name, 'wb')
				meta = u.info()
				file_size = int(meta.getheaders("Content-Length")[0])
				print ("%sDownloading: %s%s%s Bytes: %s%s%s" % (color.color('white'),color.color('yellow'),file_name,color.color('white'),color.color('red'), file_size,color.color('blue')))
				file_size_dl = 0
				block_sz = 10
				while True:
					buffer = u.read(block_sz)
					if not buffer:
						break
					file_size_dl += len(buffer)
					f.write(buffer)
					status = r"%10d  [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
					status = status + chr(8)*(len(status)+1)
					print (status,)
				f.close()
				print ('%sFile Downloaded: %s%s%s\n\n'%(color.color('cyan'),color.color('yellow'),file_name,color.color('reset')))
			except:
				print ('%sConnection Error!%s\n\n'%(color.color('red'),color.color('reset')))

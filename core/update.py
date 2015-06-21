#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
import urllib2
def start(__version__):
	url = 'https://raw.githubusercontent.com/Ali-Razmjoo/ZCR-Shellcoder-Archive/master/last_version'
	up_url = 'https://raw.githubusercontent.com/Ali-Razmjoo/ZCR-Shellcoder-Archive/master/'
	try:
		last_version = urllib2.urlopen(url).read()
		last_version = last_version.rsplit()[0]
		print last_version
	except:
		print 'Connection Error!\n\n'
	update = True
	if str(last_version) == str(__version__):
		print 'you are using the last version of software : %s'%(last_version)
		update = False
	if update is True:
		print 'your software version: %s\nlast version released: %s\n\nDownloading zcr_shellcoder_%s.zip\n\n\n'%(str(__version__),str(last_version),str(last_version))
		up_url = up_url + 'zcr_shellcoder_%s.zip'%(last_version)
		try:
			file_name = up_url.split('/')[-1]
			u = urllib2.urlopen(up_url)
			f = open(file_name, 'wb')
			meta = u.info()
			file_size = int(meta.getheaders("Content-Length")[0])
			print "Downloading: %s Bytes: %s" % (file_name, file_size)
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
				print status,
			f.close()
			print 'File Downloaded: %s\n\n'%(file_name)
		except:
			print 'Connection Error!\n\n'
#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
from core.compatible import *
from core.alert import *
import binascii
def _input(name,type,_while):
	data = None
	if _while is True:
		if type == 'any':
			while _while:
				try:
					if version() is 3:
						data = input('%s%s>%s '%(color.color('blue'),name,color.color('yellow')))
					if version() is 2:
						data = raw_input('%s%s>%s '%(color.color('blue'),name,color.color('yellow')))
					break
				except:
					write('wrong input!\n')
					pass
		if type == 'hex':
			while _while:
				try:
					if version() is 3:
						data = input('%s%s>%s '%(color.color('blue'),name,color.color('yellow')))
						binascii.b2a_hex(data[::-1].encode('latin-1')).decode('latin-1')
					if version() is 2:
						data = raw_input('%s%s>%s '%(color.color('blue'),name,color.color('yellow')))
						binascii.a2b_hex(data)
					break
				except:
					warn('you must enter a hex value\n')
					pass
		if type == 'int':
			while _while:
				try:
					if version() is 3:
						data = input('%s%s>%s '%(color.color('blue'),name,color.color('yellow')))
						int(data)
					if version() is 2:
						data = raw_input('%s%s>%s '%(color.color('blue'),name,color.color('yellow')))
						int(data)
					break
				except:
					warn('you must enter a int value\n')
					pass
	elif _while is False:
		if type == 'any':
			try:
				if version() is 3:
					data = input('%s%s>%s '%(color.color('blue'),name,color.color('yellow')))
				if version() is 2:
					data = raw_input('%s%s>%s '%(color.color('blue'),name,color.color('yellow')))
			except:
				write('wrong input!\n')
				pass
		if type == 'hex':
			try:
				if version() is 3:
					data = input('%s%s>%s '%(color.color('blue'),name,color.color('yellow')))
					binascii.b2a_hex(data[::-1].encode('latin-1')).decode('latin-1')
				if version() is 2:
					data = raw_input('%s%s>%s '%(color.color('blue'),name,color.color('yellow')))
					binascii.a2b_hex(data)
			except:
				warn('you must enter a hex value\n')
				pass
		if type == 'int':
			try:
				if version() is 3:
					data = input('%s%s>%s '%(color.color('blue'),name,color.color('yellow')))
					int(data)
				if version() is 2:
					data = raw_input('%s%s>%s '%(color.color('blue'),name,color.color('yellow')))
					int(data)
			except:
				warn('you must enter a int value\n')
				pass
	return data
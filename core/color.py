#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
#bug fix reported by John Babio in version 1.0.4 johndbabio/[at]/gmail/./com
def color(color):
	if color == 'reset':
		return '\033[0m'
	if color == 'grey':
		return '\033[1;30m'
	if color == 'red':
		return '\033[1;31m'
	if color == 'green':
		return '\033[1;32m'
	if color == 'yellow':
		return '\033[1;33m'
	if color == 'blue':
		return '\033[1;34m'
	if color == 'purple':
		return '\033[1;35m'
	if color == 'cyan':
		return '\033[1;36m'
	if color == 'white':
		return '\033[1;37m'


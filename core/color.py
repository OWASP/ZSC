#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
#bug fix reported by John Babio in version 1.0.4 johndbabio/[at]/gmail/./com
reset = '\033[0m'
grey = '\033[1;30m'
red = '\033[1;31m'
green = '\033[1;32m'
yellow = '\033[1;33m'
blue = '\033[1;34m'
purple = '\033[1;35m'
cyan = '\033[1;36m'
white = '\033[1;37m'
def color(color):
	if color == 'reset':
		return reset
	if color == 'grey':
		return grey
	if color == 'red':
		return red
	if color == 'green':
		return green
	if color == 'yellow':
		return yellow
	if color == 'blue':
		return blue
	if color == 'purple':
		return purple
	if color == 'cyan':
		return cyan
	if color == 'white':
		return white


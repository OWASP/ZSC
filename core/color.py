#!/usr/bin/env python
'''
ZCR Shellcoder

ZeroDay Cyber Research
Z3r0D4y.Com
Ali Razmjoo
'''
import sys
import ctypes
''' windows colors
blue = 0x01 
green= 0x02
light_green = 10
cy = 0x03
light_cy = 11
red  = 0x04 
light_red = 12
per = 0x05
light_per = 13
by = 0x06
light_by = 14
wh = 0x07
gr = 0x08
white = 15
light_blue = 0x09
background_blue_content_black = 0x10
background_content_blue = 0x11
background_blue_content_green = 0x12
background_blue_content_cy = 0x13
background_blue_content_red = 0x14
background_blue_content_per = 0x15
background_blue_content_by = 0x16
background_blue_content_wh = 0x17
background_blue_content_gr = 0x18
background_blue_content_light_blue = 0x19
background_green_content_black = 0x20
'''
def color(color, handle=ctypes.windll.kernel32.GetStdHandle(-11)):
	if sys.platform == 'win' or sys.platform == 'win32' or sys.platform == 'win64':
		ctypes.windll.kernel32.SetConsoleTextAttribute(handle, color)
	else:
		skip = 1
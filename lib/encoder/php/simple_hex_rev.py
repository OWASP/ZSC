#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
import binascii
import random
import string
from core.compatible import version
from core.alert import *
from core.get_input import _input
_version = version()


def encode(f):
	var_name = '$' + ''.join(
		random.choice(string.ascii_lowercase + string.ascii_uppercase)
		for i in range(50))
	data = ''
	if _version is 2:
		rev_data = binascii.b2a_hex(f)[::-1]
		data = var_name + ' = "' + rev_data + '";\n'

	if _version is 3:
		rev_data = binascii.b2a_hex(f.encode('utf8')).decode('utf8')[::-1]
		data = var_name + ' = "' + rev_data + '";\n'

	var_str = '$' + ''.join(
		random.choice(string.ascii_lowercase + string.ascii_uppercase)
		for i in range(50))
	var_counter = '$' + ''.join(
		random.choice(string.ascii_lowercase + string.ascii_uppercase)
		for i in range(50))
	var_data = '$' + ''.join(
		random.choice(string.ascii_lowercase + string.ascii_uppercase)
		for i in range(50))
	func_name = ''.join(
		random.choice(string.ascii_lowercase + string.ascii_uppercase)
		for i in range(50))
	func_argv = '$' + ''.join(
		random.choice(string.ascii_lowercase + string.ascii_uppercase)
		for i in range(50))
	f = '''
%s
function %s(%s) {
	%s = '';
	for(%s=strlen(%s)-2;%s>=0;%s-=2)
	   %s .= chr(hexdec(strrev(substr(%s,%s,2))));
	return %s;
}
%s = %s;
eval(%s(%s));

?>''' % (data, func_name, func_argv, var_str, var_counter, func_argv,
		 var_counter, var_counter, var_str, func_argv, var_counter, var_str,
		 var_data, var_name, func_name, var_data)
	return f


def start(content,cli):
	if '<?' in content or '?>' in content or '<?php' in content:
		warn(
			'We\'ve detected <? or ?> or <?php in your php code which if they wasn\'t comment, eval() will not work! so we suggest you to delete them.\n')
		if cli is False:
			answer = _input(
				'Would you let me to delete php tags for you [yes/no]? ', 'any',
				True)
		if cli is True:
			answer = 'y'
			write('Would you let me to delete php tags for you [yes/no]? yes\n')
		if answer == 'yes' or answer == 'y':
			content = content.replace('<?php', '').replace('<?', '').replace(
				'?>', '')
		elif answer == 'no' or answer == 'n':
			pass
		else:
			warn('You had to answer with yes or no, We count that as "no"\n')
	return str(str('<?php \n/*\n') + str(content.replace('*/', '*_/')) + str(
		'\n*/') + str(encode(content)) + str('\n'))

#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
import binascii
import random
import string
from core.compatible import version
from core.alert import *
from core.get_input import _input
_version = version()
def encode(f):
	hex_arr = []
	val_names = []
	data = ''
	eval = ''
	n = 0
	m = 0
	for line in f:
		if _version is 2:
			hex_arr.append(str(binascii.b2a_hex(line)))
		if _version is 3:
			hex_arr.append(str((binascii.b2a_hex(str(line).encode('latin-1'))).decode('latin-1')))
	length = len(hex_arr)
	while(length != 0):
		val_names.append(''.join(random.choice(string.ascii_lowercase+string.ascii_uppercase) for i in range(50)))
		length -= 1
	for hex in hex_arr:
		data += '$' + val_names[n] + ' = "' + str(hex) + '";\n'
		n+=1
	while(m<=n-1):
		eval += '$' + val_names[m] + '.'
		m+=1
	var_str = '$' + ''.join(random.choice(string.ascii_lowercase+string.ascii_uppercase) for i in range(50))
	var_counter = '$' + ''.join(random.choice(string.ascii_lowercase+string.ascii_uppercase) for i in range(50))
	var_data = '$' + ''.join(random.choice(string.ascii_lowercase+string.ascii_uppercase) for i in range(50))
	func_name = ''.join(random.choice(string.ascii_lowercase+string.ascii_uppercase) for i in range(50))
	func_argv = '$' + ''.join(random.choice(string.ascii_lowercase+string.ascii_uppercase) for i in range(50))
	f = '''

%s
function %s(%s) {
    for(%s=0;%s<strlen(%s);%s+=2)
       %s .= chr(hexdec(substr(%s,%s,2)));

    return %s;
}
%s = %s;
eval(%s(%s));

?>'''%(data,func_name,func_argv,var_counter,var_counter,func_argv,var_counter,var_str,func_argv,var_counter,var_str,var_data,eval[:-1],func_name,var_data)
	return f

def start(content):
	if '<?' in content or  '?>' in content or '<?php' in content:
		warn('We\'ve detected <? or ?> or <?php in your php code which if they wasn\'t comment, eval() will not work! so we suggest you to delete them.\n')
		answer = _input('Would you let me to delete php tags for you [yes/no]? ','any',True)
		if answer == 'yes' or answer == 'y':
			content = content.replace('<?php','').replace('<?','').replace('?>','')
		elif answer == 'no' or answer == 'n':
			pass
		else:
			warn('You had to answer with yes or no, We count that as "no"\n')
	return str(str('<?php \n/*\n')+str(content.replace('*/','*_/'))+str('\n*/') + str(encode(content))+str('\n'))
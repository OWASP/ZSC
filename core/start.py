#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''
import sys
#from core import update as upd
from core.compatible import version
__version__ = '1.1.0'
__key__ = 'ST'
__release_date__ = '2016 July 22'
from core import color


def logo():
    print(color.color('red') + '''
  ______          __      _____ _____    ______ _____  _____ 
 / __ \ \        / /\    / ____|  __ \  |___  // ____|/ ____|
| |  | \ \  /\  / /  \  | (___ | |__) |    / /| (___ | |     
| |  | |\ \/  \/ / /\ \  \___ \|  ___/    / /  \___ \| |     
| |__| | \  /\  / ____ \ ____) | |       / /__ ____) | |____ 
 \____/   \/  \/_/    \_\_____/|_|      /_____|_____/ \_____|
                                                             
                                                              
''' + color.color('cyan') + '\t\t' + color.color(
        'green') + 'OWASP' + color.color('cyan') +
          ' ZeroDay Cyber Research Shellcoder\n' + color.color('reset'))


def sig():
    print('''%s
|----------------------------------------------------------------------------|
|%sVisit%s https://www.%sowasp%s.org/index.php/OWASP_ZSC_Tool_Project ---------------|
|----------------------------------------------------------------------------|%s'''
          % (color.color('blue'), color.color('red'), color.color('blue'),
             color.color('red'), color.color('blue'), color.color('reset')))


def inputcheck():
    print(color.color('yellow') + '''
[+] Wrong input, Check Help Menu ,Execute: zsc ''' + color.color('red') + '-h'
          + '\n' + color.color('reset'))
    sys.exit(sig())


def about():
    write('\n')
    info = [
        ['Code', 'https://github.com/Ali-Razmjoo/OWASP-ZSC'], [
            'Contributors',
            'https://github.com/Ali-Razmjoo/OWASP-ZSC/graphs/contributors'
        ], ['API', 'http://api.z3r0d4y.com/'],
        ['Home', 'http://zsc.z3r0d4y.com/'],
        ['Mailing List',
         'https://groups.google.com/d/forum/owasp-zsc'],
        ['Contact US Now', 'owasp-zsc[at]googlegroups[dot]com']
    ]
    for section in info:
        write('%s%s%s: %s%s%s\n' %
              (color.color('red'), section[0], color.color('reset'),
               color.color('yellow'), section[1], color.color('reset')))
    sig()


def _version():
    write('\n')
    write('%sOWASP ZSC Version: %s%s\n' %
          (color.color('cyan'), color.color('red'), __version__))
    write('%sKey: %s%s\n' % (color.color('cyan'), color.color('red'), __key__))
    write('%sRelease Date: %s%s\n' %
          (color.color('cyan'), color.color('red'), __release_date__))
    sig()

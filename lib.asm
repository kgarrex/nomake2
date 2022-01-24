
%ifidn __?OUTPUT_FORMAT?__ , win32
	%define NEWLINE 13, 10
%elifidn __?OUTPUT_FORMAT?__, elf32
	%define NEWLINE 10
%endif


; Used for writeable static data initialized to zero
[section .bss]

;COFF Header
struc pe_file_header
	Signature:              resb  1
	Machine:                resw  1
	NumberOfSections:       resw  1
	TimeDateStamp:          resd  1
	PointerToSymbolTable:   resd  1
	NumberOfSymbols:        resd  1
	SizeOfOptionalHeader:   resd  1
	Characteristics:        resd  1 
;Standard COFF Fields
	Magic:                  resd  1
endstruc


; Used for writeable data with some initialized non-zero content.
; Thus, the data section contains information that could be changed
; during application execution and this section must be copied for
; every instance.
[section .data]

%define sizeptr 4

; Code section, contains the program's instructions - read-only/executable
[section .text] 


SIZEPTR equ 4


global _testProc@4
global _bswap16@4
global _bswap32@4
global _bswap64@8


%macro return 1
	add esp, %1
	jmp [esp-%1]
%endmacro


_testProc@4:
	sub esp, 4
	mov [esp], ebp

	xor eax, eax
	mov eax, [esp+12]

	;mov ebp, [esp]
	add esp, 4
	ret 4


_bswap16@4:
	mov eax, [esp+SIZEPTR]
	shl eax, 16
	bswap eax
	add esp, 8 
	jmp [esp-8]


_bswap32@4:
	mov eax, [esp+8]
	;shl eax, 16
	ret 4



;dns_add_name proc public



;memcpy proc public dest:ptr byte, src:ptr byte, count:dword
	;movdqa
	;ret
;memcpy endp


[section .rdata]
[section .rsrc]
;[section .reloc]

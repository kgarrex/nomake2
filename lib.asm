
;COFF Header
pe_file_header struct

	signature              dword ?
	machine                word  ?
	NumberOfSections       word  ?
	TimeDateStamp          dword ?
	PointerToSymbolTable   dword ?
	NumberOfSymbols        dword ?
	SizeOfOptionalHeader   dword ?
	Characteristics        dword ? 

	;Standard COFF Fields
	Magic                  dword ?

pe_file_header ends


.model flat, stdcall


.code

testProc proc public n1:dword
	
	sub esp, 4
	mov [esp], ebp

	xor eax, eax
	mov eax, [esp+12]

	;mov ebp, [esp]
	add esp, 4
	ret 4

testProc endp


memcpy proc public dest:ptr byte, src:ptr byte, count:dword

	
;	movdqa
memcpy endp

end

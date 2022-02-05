
global @jasm_init@12
global @jasm_parse@8


; 3 bit parser state values
ARR_OPT_VAL equ 0
ARR_REQ_VAL equ 1
ARR_END_VAL equ 2
OBJ_OPT_KEY equ 3
OBJ_REQ_KEY equ 4
OBJ_END_KEY equ 5
OBJ_REQ_VAL equ 6
OBJ_END_VAL equ 7


[section .bss] ; data?

struc parser_state
	phase:   resb 1
endstruc



[section .data]


table dd                                       \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0



[section .text]

;leaveNamespace:
;
; 
;
; struct parser_state {
; 	word phase
;	byte *utf8_json_string
;	size_t length
;	size_t lineno
;	char stack_index
;	void *ns_stack[64]
; };
;
;




; root         : [reg
; phase        : word [reg]
; ns_stack     : [reg+4]
; buffer       : []
; buflen       : []
; lineno       : []
; stack_index  : []
; alloc        : []
; free         : []

MAX_KEY_LENGTH         equ 31
MAX_NAMESPACE_LEVEL    equ 80
PHASE_OFFSET           equ 4
NS_STACK_OFFSET        equ 32
LINENO_OFFSET          equ 16 
STACKIDX_OFFSET        equ 20
ALLOC_OFFSET           equ 24
FREE_OFFSET            equ 28
STRING_OFFSET          equ 8
LENGTH_OFFSET          equ 12




@jasm_init@12:
	mov [ecx+ALLOC_OFFSET],       dword edx   ; alloc = edx
	mov edx, [esp+4]                          ; get jasm_free_t off stack
	mov [ecx+FREE_OFFSET],        dword edx   ; free = edx
	mov [ecx+PHASE_OFFSET],       dword 0x0
	mov [ecx+STACKIDX_OFFSET],    dword 0x0
	mov [ecx+LINENO_OFFSET],      dword 0x0
	mov [ecx+LENGTH_OFFSET],      dword 0x0   ; zero the string length
	mov [ecx+STRING_OFFSET],      dword 0x0   ; zero the string

	mov eax, 0x1
	cpuid

	add esp, 8                                ; fastcall stack cleanup
	jmp [esp-8]


; int __cdecl parser_load(state *, char *utf8, size_t utf8len);
_jasm_load_buf:
	; set the json string to parse and length
	; set the namespace stack index to 0 (xor idx, idx)
	; set the line number to 1
	; set the phase to 0
	jmp [esp] ; return


; Skip the white space in a json document
; 0x20 - space
; 0x09 - horizontal tab
; 0x0d - carriage return
; 0x0a - line feed
; 0x0c - page feed
; 0x0b - vertical tab
skipws:





; @jasm_parse@8 - JSON parser in pure assembly
; .bgn - Begin parser
; .ens - Enter namespace
; .aov - Array Optional Value
; .arv - Array Required Value
; .aev - Array End Value
; .ook - Object Optional Key
; .ork - Object Required Key
; .oek - Object End Key
; .orv - Object Required Value
; .oev - Object End Value
; .lns - Leave namespace
; .eob - End of Buffer
; .fin - Finalize parser



; 0x5b - left square brackt
; 0x5d - right square bracket
; 0x7b - left curly brace
; 0x7d - right curly brace
; 0x2c - comma
; 0x3a - colon
; 0x22 - double quote
; 0x5c - backslash
; 0x66 - f (false)
; 0x74 - t (true)
; 0x6e - n (null)

@jasm_parse@8:
	sub esp, 8   ; create space on the stack for locals

	mov ebp, ecx
	movzx eax, word [ebp]       ; eax = parser->phase
	add eax, .bgn               ; add .bgn address to phase offset
	jmp eax                     ; jump to phase address

.bgn:
	; if parser->phase == 0, start parsing from scratch
	; skip white space
	; check if first char start of array '[' or object '{'
	; set the type on the current namespace

.ens:
	; if the type of the current namespace is an object
	; jmp to ook


.aov:
	mov eax, .aov - .bgn; store the jmp address
	mov [ebp], eax
	; skip whitespace
	 
	cmp byte [eax], 0x5d               ; if(*ptr == ']') 
	jz .lns
.arv:
	mov eax, .arv - .bgn
	mov [ebp+0], eax
	; skip whitespace

	
.aev:
	mov eax, .aev - .bgn
	mov [ebp+0], eax
	; skip whitespace
.ook:
	mov eax, .ook - .bgn
	mov [ebp+0], eax
	; skip whitespace
.ork:
	mov eax, .ork - .bgn
	mov [ebp+0], eax
	; skip whitespace
.oek:
	mov eax, .oek - .bgn
	mov [ebp+0], eax
	; skip whitespace
.orv:
	mov eax, .orv - .bgn
	mov [ebp+0], eax
	; skip whitespace
.oev:
	mov eax, .oev - .bgn
	mov [ebp+0], eax
	; skip whitespace

.lns:
	; if(curns == rootns) jmp .finalize 
	; else set previous node to the current namespace
	; decrement the stack index and set the current namespace to the previous
	; namespace on the stack
	; advance the location pointer by 1
	; jmp enter_namespace

.eob:
	; out of buffer space but parser has not closed last namespace
	; this means we must exit function but make reentrant

.fin:


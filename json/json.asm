
global _parseJson@8


; 3 bit parser state values
ARR_OPT_VAL equ 0
ARR_REQ_VAL equ 1
ARR_END_VAL equ 2
OBJ_OPT_KEY equ 3
OBJ_REQ_KEY equ 4
OBJ_END_KEY equ 5
OBJ_REQ_VAL equ 6
OBJ_END_VAL equ 7


[section .bss]

struc parser_state
	phase:   resb 1
endstruc

[section .data]




[section .text]

;leaveNamespace:

; 
;
; struct parser_state {
; 	word phase
;	byte *utf8_json_string
;	size_t length
;	size_t lineno
;	char stack_index
;	void *ns_stack[32]
; };
;
;



; int __cdecl parser_load(state *, char *utf8, size_t utf8len);
_parser_load:
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

	



; @parseJson@8 - JSON parser in pure assembly
; .bgn - Initialize parser
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

; phase : word [ebp+0]
; ns_stack : [ebp+
; root_ns : [ebp

; 0x5b - left square brackt
; 0x5d - right square bracket
; 0x7b - left curly brace
; 0x7d - right curly brace
; 0x2c - comma
; 0x3a - colon
; 0x22 - double quote
; 0x5c - backslash

@parseJson@8:
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
	jz .leave_namespace
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

.eob
	; out of buffer space but parser has not closed last namespace
	; this means we must exit function but make reentrant

.fin:


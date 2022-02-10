
global @jasm_init@8
global @jasm_parse@8
global @jasm_set_var@12
global @jasm_get_var@8
global @jasm_rename_key@12
global @jasm_find_key@12


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


skipws_table dd                                \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0





[section .text]



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

; %if 32bit 512
NUM_HASH_SLOTS         equ 79
NUM_NAMESPACE_LEVEL    equ 32 


JASM_MAX_SIZE          equ 512  ; This is a compile time constant!!!

SLOTS_OFFSET           equ PADDING1_OFFSET-(NUM_HASH_SLOTS * 4)
PADDING1_OFFSET        equ RSLTPTR_OFFSET - 28 
RSLTPTR_OFFSET         equ FOCUS_OFFSET - 4
FOCUS_OFFSET           equ ROOT_OFFSET - 4
ROOT_OFFSET            equ PHASE_OFFSET - 4
PHASE_OFFSET           equ BUFFER_OFFSET - 4
BUFFER_OFFSET          equ BUFSIZE_OFFSET - 4
BUFSIZE_OFFSET         equ LINENO_OFFSET - 4
LINENO_OFFSET          equ STACKIDX_OFFSET - 4
STACKIDX_OFFSET        equ PADDING2_OFFSET - 1
PADDING2_OFFSET        equ FLAGS_OFFSET - 1
FLAGS_OFFSET           equ RESULT_OFFSET - 1
RESULT_OFFSET          equ ALLOC_PROC_OFFSET - 1
ALLOC_PROC_OFFSET      equ FREE_PROC_OFFSET - 4
FREE_PROC_OFFSET       equ NS_STACK_OFFSET - 4
NS_STACK_OFFSET        equ JASM_MAX_SIZE-(NUM_NAMESPACE_LEVEL*4)


BGN                    equ @jasm_parse@4.bgn - @jasm_parse@4
OEV                    equ @jasm_parse@4.oev - @jasm_parse@4.bgn


JASM_VAR_BUFFER         equ 0
JASM_vAR_ALLOC          equ 1
JASM_VAR_FREE           equ 2
JASM_VAR_BUFSIZE        equ 3
JASM_VAR_RESULT_POINTER equ 4
JASM_VAR_FLAGS          equ 5


JASM_PARSE_FLAG_PRESERVE_KEYS  equ 0x1    ; allow storage of field names, use mainly to parse and write
JASM_PARSE_FLAG_PRESERVE_CASE  equ 0x2    ; preserve the casing of keys
JASM_PARSE_FLAG_STRICT_KEYS    equ 0x4    ; keys are only allow alphanumeric and _ chars
JASM_PARSE_FLAG_NUM_NOTATIONS  equ 0x8    ; allow hex, octal and binary numbers
JASM_PARSE_FLAG_ALLOW_DUP_KEYS equ 0x10   ; allow duplicate keys in an object; TODO optimize or not?



@jasm_init@8:
    ;test edx, 0x200 
    ;test edx, 0x800
    mov [ecx+FLAGS_OFFSET],       byte 0x0010 ; set parse flags
    lea eax, [ecx+RESULT_OFFSET]
    mov [ecx+RSLTPTR_OFFSET], eax
    mov [ecx+ALLOC_PROC_OFFSET],  dword 0x0   ; alloc = edx
    mov [ecx+FREE_PROC_OFFSET],   dword 0x0   ; free = edx
    mov [ecx+PHASE_OFFSET],       dword 0x0
    mov [ecx+STACKIDX_OFFSET],    dword 0x0
    mov [ecx+BUFSIZE_OFFSET],     dword 0x0   ; zero the string length
    mov [ecx+LINENO_OFFSET],      dword 0x0
    mov [ecx+BUFFER_OFFSET],      dword 0x0   ; zero the buffer * 
    mov [ecx+FOCUS_OFFSET],       dword 0x0

    mov eax, 0x1
    cpuid

    add esp, 4                                ; fastcall stack cleanup
    jmp [esp-4]




[section .rdata]

table: dw \
    @jasm_set_var@12.buffer - @jasm_set_var@12,     \
    @jasm_set_var@12.bufsize - @jasm_set_var@12,    \
    @jasm_set_var@12.alloc - @jasm_set_var@12,      \
    @jasm_set_var@12.free - @jasm_set_var@12,       \
    @jasm_set_var@12.rsltptr - @jasm_set_var@12,    \
    @jasm_set_var@12.flags - @jasm_set_var@12, \

table_size dd $-table


[section .text]

;***************************************************
; ecx - jasm_t *
; edx - varid
; [esp+4] - value
;***************************************************
@jasm_set_var@12:
    mov eax, [esp+4]
    mov edx, [table+edx*4]
    add edx, @jasm_set_var@12
    jmp edx 	

    .buffer:
    mov [ecx+BUFFER_OFFSET], eax
    jmp .exit

    .bufsize:
    mov [ecx+BUFSIZE_OFFSET], eax
    jmp .exit

    .alloc:
    mov [ecx+ALLOC_PROC_OFFSET], eax
    jmp .exit

    .free:
    mov [ecx+FREE_PROC_OFFSET], eax
    jmp .exit

    .rsltptr:
    test eax, 0
    jnz short .rsltptr_nz ; TODO get size of lea instruction and just jump by that
    lea eax, [ecx+RESULT_OFFSET]
	.rsltptr_nz:
        mov [ecx+RSLTPTR_OFFSET], eax
    jmp .exit

    .flags:
    mov [ecx+FLAGS_OFFSET], eax
    jmp .exit


    .exit:
    add esp, 8                                ; fastcall stack cleanup
    jmp [esp-8]





[section .rdata]

jasm_set_table db                              \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0



[section .text]

;*****************************************************
; ecx = jasm_t *
; edx = varid
; [esp+4] = *value
;*****************************************************
@jasm_get_var@12:
	.get_buffer:
	.get_busize:
	.get_alloc:

	add esp, 4
	jmp [esp-4]                               ; fastcall stack cleanup



; int __cdecl parser_load(state *, char *utf8, size_t utf8len);
_jasm_load_buf:
	; set the json string to parse and length
	; set the namespace stack index to 0 (xor idx, idx)
	; set the line number to 1
	; set the phase to 0
	jmp [esp] ; return

;*******************************************************************
; skipws - Skip the white space in a json document
;
; 0x09 - horizontal tab
; 0x0a - line feed
; 0x0d - carriage return
; 0x20 - space
;*********************************************************************
skipws:
	; subtract 1
	; clear 2 msb bits  and 0x2f
	; compare index in array
	; if greater than 0, add number of chars
	;mov reg, 
.loop:
	;sub byte [reg], 1
	;and [reg], 0x2f
	;test reg, reg 



;**********************************************************************
; Calculate the length of a zero-terminated string
;
;**********************************************************************
strlen:
    vmovdqu  xmm1, [edi]
    vpcmpeqb xmm1, xmm2, xmm3                                   ; compare the bytes
    ;vpmovmskb ; create mask of msb
    ;bsf       ; find bit set to 1
    ;jz        ; no '0' found, add vec size to length, progress pointer and try again
    add      edi, 16
	



;*********************************************************************
; jasm_parse - JSON parser in pure assembly
;
; .bgn - Begin parser
;        Initialize the parser and create the root namespace
;
; .ens - Enter namespace
;        Enter a new a namespace (array/object) or reenter a namespace
;        after leaving a nested namespace
;
; .aov - Array Optional Value
;        The parser is at the start of a new array and is expecting
;        the ending bracket or a new value
;
; .abv - Array Begin Value
;        The parser is expecting a new array value. Any invalid value
;        symbols results in an error
;
; .aev - Array End Value
;        The parser has just passed an array value and is expecting
;        either a comma before a new value or the ending bracket
;
; .ook - Object Optional Key
;        The parser is at the start of a new object and is expecting
;        the ending curly brace or a new value
;
; .obk - Object Begin Key
;        Expecting a new object value. Any invalid value symbol
;        results in an error.
;
; .oek - Object End Key
;        The end of a key string.
;
; .obv - Object Begin Value
;
; .oev - Object End Value
;
; .lns - Leave namespace
;
; .eob - End of Buffer
;
; .fin - Finalize parser
;
; .err - Error
;
;
; eax  -
; ebx  -
; ecx  - length
; edx  - 
; ebp  - jasm_t *
; esi  - stack index
; edi  - string
; esp  -
; 
;
; 0x5b - left square bracket
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
;*********************************************************************

@jasm_parse@4:
	sub esp, 8   ; create space on the stack for locals

	mov ebp, ecx
	;movzx eax, word [ecx+PHASE_OFFSET]        ; eax = parser->phase
	mov eax, dword [ecx+PHASE_OFFSET]         ; eax = parser->phase
	add eax, .bgn                             ; add .bgn address to phase offset
	jmp eax                                   ; jump to phase address

	;lea edi, [ecx+esi*4+NS_STACK_OFFSET]     ; current namespace pointer


.sws:   ; skip whitespace
	jmp eax

.bgn:
	; first, if bufsize is zero we assume buffer is a zero-terminated string
	; we need to find string length
	; if parser->phase == 0, start parsing from scratch
	; skip white space
	; check if first char start of array '[' or object '{'
	; set the type on the current namespace

.ens:
	; if the type of the current namespace is an object
	; jmp to ook


.aov:   ; should just set the value to nullarr and not create a new namespace object
	mov eax, .aov - .bgn; store the jmp address
	mov [ebp], eax
	; call skipws
	 
	test byte [eax], 0x5d               ; if(*ptr == ']') 
	je .lns

.abv:
	mov eax, .abv - .bgn
	mov [ebp+0], eax
	; call skipws
	; validate value
	; 

	
.aev:
	mov eax, .aev - .bgn
	mov [ebp+0], eax
	; skip whitespace

	test byte [eax], 0x2c               ; if(*ptr == ',')
	je .abv
	test byte [eax], 0x5d               ; if(*ptr == ']')
	je .lns
	; error here


.ook:   ; should just set the value to nullobj and not create a new namespace object
	mov eax, .ook - .bgn
	mov [ebp+0], eax
	call .sws

	test byte [eax], 0x7d               ; if(*ptr == '}')
	je .lns

.obk:
	mov eax, .obk - .bgn
	mov [ecx+0], eax
	; skip whitespace
	test byte [ebp], 0x22                    ; if(*ptr == '"')
	jne .err

.oek:
	mov eax, .oek - .bgn
	mov [ebp+0], eax
	; skip whitespace
	test byte [eax], 0x3a                ; if(*ptr == ':')
	;jne .err

.obv:
	mov eax, .obv - .bgn
	mov [ebp+0], eax
	; skip whitespace

.oev:
	mov eax, .oev - .bgn
	mov [ebp+0], eax
	; skip whitespace

	test byte [eax], 0x2c                ; if(*ptr == ',')
	je .obk
	test byte [eax], 0x7d                ; if(*ptr == '}')
	je .lns

.lns:
	; if(curns == rootns) jmp .finalize 
	; else set previous node to the current namespace
	; decrement the stack index and set the current namespace to the previous
	sub esi, 1
	; namespace on the stack
	; advance the location pointer by 1
	; jmp enter_namespace

.eob:
	; out of buffer space but parser has not closed last namespace
	; this means we must exit function but make reentrant

.fin:

.err:

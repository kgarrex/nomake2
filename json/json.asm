


; bytes  | bits | type  |  .data |  .bss
; -------+------+-------+-----------------
;  1     | 8    | byte  | db     | resb
;  2     | 16   | word  | dw     | resw
;  4     | 32   | dword | dd     | resd
;  8     | 64   | qword | dq     | resq
;  10    | 80   | tword | dt     | rest
;  16    | 128  | oword | do/ddq | reso/resdq
;  32    | 256  | yword | dy     | resy
;  64    | 512  | zword | dz     | resz




REGSIZE equ 4





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
LINENO_OFFSET          equ FLAGS_OFFSET - 4
FLAGS_OFFSET           equ STACKIDX_OFFSET - 2
STACKIDX_OFFSET        equ RESULT_OFFSET - 1
RESULT_OFFSET          equ ALLOC_PROC_OFFSET - 1
ALLOC_PROC_OFFSET      equ FREE_PROC_OFFSET - 4
FREE_PROC_OFFSET       equ NS_STACK_OFFSET - 4
NS_STACK_OFFSET        equ JASM_MAX_SIZE-(NUM_NAMESPACE_LEVEL*4)


BGN                    equ internal_parse128.bgn - internal_parse128 
OEV                    equ internal_parse128.oev - internal_parse128.bgn


JASM_VAR_BUFFER         equ 0
JASM_vAR_ALLOC          equ 1
JASM_VAR_FREE           equ 2
JASM_VAR_BUFSIZE        equ 3
JASM_VAR_RESULT_POINTER equ 4
JASM_VAR_FLAGS          equ 5


JASM_FLAG_PARSE_PRESERVE_KEYS  equ 0x01    ; allow storage of field names, use mainly to parse and write
JASM_FLAG_PARSE_PRESERVE_CASE  equ 0x02    ; preserve the casing of keys
JASM_FLAG_PARSE_STRICT_KEYS    equ 0x04    ; keys are only allow alphanumeric and _ chars
JASM_FLAG_PARSE_NUM_NOTATIONS  equ 0x08    ; allow hex, octal and binary numbers
JASM_FLAG_PARSE_NO_DUP_KEYS    equ 0x10    ; no duplicate keys in an object; TODO optimize or not?



;**********************************************************************
;
; Calculate the length of a zero-terminated string
;
; edi = char *str
;
;**********************************************************************
internal_strlen128:
    vpxor xmm1, xmm1
    .loop:
    vpcmpeqb xmm0, xmm1, oword [ecx]
    vpmovmskb eax, xmm0
    bsf eax, eax
    jnz .exit
    add ecx, 16
    jmp .loop
    .exit:
    sub ecx, edi
    add eax, ecx
    pop edi
    add esp, 4
    jmp [esp-4]


internal_strlen256:
    push edi ;temp
    mov edi, ecx
    vpxor ymm1, ymm1                              ; zero-out register for comparison
    ;mov ecx, edi
    .loop:
    vpcmpeqb ymm0, ymm1, yword [ecx]              ; compare the bytes
    vpmovmskb eax, ymm0
    bsf eax, eax
    jnz .exit
    add ecx, 32 
    jmp .loop
    .exit:
    sub ecx, edi
    ;add ecx, eax
    add eax, ecx ;temp
    pop edi ;temp
    add esp, 4
    jmp [esp-4]



; void memcpy(dest, src, nbytes)
; edi = dest
; esi = src
; ecx = nbytes 
internal_memcpy128:
    ;test ecx, 0xfffffff6

    ;transfer 256 bytes per unrolled loop
    vmovdqa xmm0, [esi]
    vmovdqa [edi], xmm0
    vmovdqa xmm0, [esi+16]
    vmovdqa [edi], xmm0
    vmovdqa xmm0, [esi+32]
    vmovdqa [edi], xmm0
    vmovdqa xmm0, [esi+48]
    vmovdqa [edi], xmm0
    vmovdqa xmm0, [esi+64]
    vmovdqa [edi], xmm0
    vmovdqa xmm0, [esi+80]
    vmovdqa [edi], xmm0
    vmovdqa xmm0, [esi+96]
    vmovdqa [edi], xmm0
    vmovdqa xmm0, [esi+112]
    vmovdqa [edi], xmm0
    vmovdqa xmm0, [esi+128]
    vmovdqa [edi], xmm0
    vmovdqa xmm0, [esi+144]
    vmovdqa [edi], xmm0
    vmovdqa xmm0, [esi+160]
    vmovdqa [edi], xmm0
    vmovdqa xmm0, [esi+176]
    vmovdqa [edi], xmm0
    vmovdqa xmm0, [esi+192]
    vmovdqa [edi], xmm0
    vmovdqa xmm0, [esi+208]
    vmovdqa [edi], xmm0
    vmovdqa xmm0, [esi+224]
    vmovdqa [edi], xmm0
    vmovdqa xmm0, [esi+240]
    vmovdqa [edi], xmm0
    ;sub edx, 


;00000010 00000001


;void memcpy(dest, src, nbytes)
; edi = dest
; esi = src
; ecx = nbytes
internal_memcpy256:

    ror ecx, 10

    ; if less than 32 bytes...
    vmovdqa xmm0, [esi]
    vmovdqa [edi], xmm0
    vmovdqa xmm0, [esi+16]
    vmovdqa [edi], xmm0

    ; if greater than or equal to 32 bytes...
    ;transfer 512 bytes per unrolled loop
    vmovdqa ymm0,      [esi+0]
    vmovdqa [edi+0],   ymm0
    vmovdqa ymm0,      [esi+32]
    vmovdqa [edi+32],  ymm0
    vmovdqa ymm0,      [esi+64]
    vmovdqa [edi+64],  ymm0
    vmovdqa ymm0,      [esi+92]
    vmovdqa [edi+92],  ymm0
    vmovdqa ymm0,      [esi+128]
    vmovdqa [edi+128], ymm0
    vmovdqa ymm0,      [esi+160]
    vmovdqa [edi+160], ymm0
    vmovdqa ymm0,      [esi+192]
    vmovdqa [edi+192], ymm0
    vmovdqa ymm0,      [esi+224]
    vmovdqa [edi+224], ymm0
    vmovdqa ymm0,      [esi+256]
    vmovdqa [edi+256], ymm0
    vmovdqa ymm0,      [esi+288]
    vmovdqa [edi+288], ymm0
    vmovdqa ymm0,      [esi+320]
    vmovdqa [edi+320], ymm0
    vmovdqa ymm0,      [esi+352]
    vmovdqa [edi+352], ymm0
    vmovdqa ymm0,      [esi+384]
    vmovdqa [edi+384], ymm0
    vmovdqa ymm0,      [esi+416]
    vmovdqa [edi+416], ymm0
    vmovdqa ymm0,      [esi+448]
    vmovdqa [edi+448], ymm0
    vmovdqa ymm0,      [esi+480]
    vmovdqa [edi+480], ymm0
 






;-------- PUBLIC API ----------------

global @jasm_init@4
global @jasm_parse@4
global _jasm_set
global @jasm_get@8
global @jasm_rename_key@12
global @jasm_find_key@12
global @jasm_get_value@12
global @jasm_set_value@12
global @jasm_add_value@4
global @jasm_value_type@4

; The following exports are for debug purposes only
global @jasm_strlen@4




;**********************************************************************
;
; jasm_init(jasm_t *) - Initialize the jasm library 
; ecx = jasm_t *
;
;**********************************************************************
@jasm_init@4:
    ;test edx, 0x200 
    ;test edx, 0x800
    mov [ecx+FLAGS_OFFSET],        word 0x0 ; set flags
    lea eax, [ecx+RESULT_OFFSET]
    mov [ecx+RSLTPTR_OFFSET], eax
    mov [ecx+ALLOC_PROC_OFFSET],  dword 0x0   ; alloc = edx
    mov [ecx+FREE_PROC_OFFSET],   dword 0x0   ; free = edx
    mov [ecx+PHASE_OFFSET],       dword 0x0
    mov [ecx+STACKIDX_OFFSET],    dword 0x1
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
    _jasm_set.buffer  - _jasm_set, \
    _jasm_set.alloc   - _jasm_set, \
    _jasm_set.rsltptr - _jasm_set, \
    _jasm_set.flags   - _jasm_set, \

table_size dd $-table


[section .text]

;***************************************************
; [esp+4]  - jasm_t *
; [esp+8]  - varid
; [esp+12] - value
;***************************************************
_jasm_set:
    mov edx, [esp+4]              ; get jasm_t *
    mov ecx, [esp+8]              ; get id value
    mov eax, [table+ecx*4]
    add eax, _jasm_set
    jmp eax

    .buffer:
    mov eax, [esp+12]
    mov [edx+BUFFER_OFFSET], eax 
    mov eax, [esp+16]
    ; may want to test buffer size here
    mov [edx+BUFSIZE_OFFSET], eax
    jmp [esp]

    .alloc:
    mov eax, [esp+12]
    mov [edx+ALLOC_PROC_OFFSET], eax 
    mov eax, [esp+16]
    ; may want to test buffer size here
    mov [edx+FREE_PROC_OFFSET], eax
    jmp [esp]

    .rsltptr:
    mov eax, [esp+12]
    test eax, 0
    jnz short .rsltptr_nz ; TODO get size of lea instruction and just jump by that
    lea eax, [edx+RESULT_OFFSET]
    .rsltptr_nz: mov [edx+RSLTPTR_OFFSET], eax
    jmp [esp]

    .flags:
    mov eax, [esp+12]
    mov [edx+FLAGS_OFFSET], eax
    jmp [esp]






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

	add esp, 8
	jmp [esp-8]                               ; fastcall stack cleanup





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





wstable: dq                                                                         \
    0x2020202020202020, 0x2020202020202020, 0x2020202020202020, 0x2020202020202020, \
    0x2020202020202020, 0x2020202020202020, 0x2020202020202020, 0x2020202020202020, \
    0x0D0D0D0D0D0D0D0D, 0x0D0D0D0D0D0D0D0D, 0x0D0D0D0D0D0D0D0D, 0x0D0D0D0D0D0D0D0D, \
    0x0D0D0D0D0D0D0D0D, 0x0D0D0D0D0D0D0D0D, 0x0D0D0D0D0D0D0D0D, 0x0D0D0D0D0D0D0D0D, \
    0x0A0A0A0A0A0A0A0A, 0x0A0A0A0A0A0A0A0A, 0x0A0A0A0A0A0A0A0A, 0x0A0A0A0A0A0A0A0A, \
    0x0A0A0A0A0A0A0A0A, 0x0A0A0A0A0A0A0A0A, 0x0A0A0A0A0A0A0A0A, 0x0A0A0A0A0A0A0A0A, \
    0x0909090909090909, 0x0909090909090909, 0x0909090909090909, 0x0909090909090909, \
    0x0909090909090909, 0x0909090909090909, 0x0909090909090909, 0x0909090909090909


DQU   equ 0
COM   equ 0
ZER   equ 0
ONE   equ 0
TWO   equ 0
THR   equ 0
FOU   equ 0
FIV   equ 0
SIX   equ 0
SEV   equ 0
EIG   equ 0
NIN   equ 0
NUM   equ 0
COL   equ 0
LSB   equ 0
BSL   equ 0
RSB   equ 0
FAL   equ 0
NUL   equ 0
TRU   equ 0
LCB   equ 0
RCB   equ 0

;TODO This is a good place to optimize for memory or speed
;TODO if speed use label address, if memory use offset (ex. jmptable dw/dd/dq)
jmptable: db \
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, \
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, \
    0x0, 0x0, DQU, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, COM, 0x0, 0x0, 0x0, \
    ZER, ONE, TWO, THR, FOU, FIV, SIX, SEV, EIG, NIN, COL, 0x0, 0x0, 0x0, 0x0, 0x0, \
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, \
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, LSB, BSL, RSB, 0x0, 0x0, \
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, FAL, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, NUL, 0x0, \
    0x0, 0x0, 0x0, 0x0, TRU, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, LCB, 0x0, RCB, 0x0, 0x0, \


; 3 bit parser state values
ARR_OPT_VAL equ 0
ARR_REQ_VAL equ 1
ARR_END_VAL equ 2
OBJ_OPT_KEY equ 3
OBJ_REQ_KEY equ 4
OBJ_END_KEY equ 5
OBJ_REQ_VAL equ 6
OBJ_END_VAL equ 7



IS_OBJECT   equ 0x01
IS_ARRAY    equ 0x02
IS_STRING   equ 0x04
IS_NUMBER   equ 0x08
IS_BOOLEAN  equ 0x10
IS_NULL     equ 0x20
NODQU_BIT   equ 0x40
ALLOW_QUOTES






@jasm_parse@4:
    
    ;call internal_parse128
    add esp, 4
    jmp [esp-4]




;*********************************************************************
; jasm_parse - JSON parser in pure assembly
;
; Parser States:
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
; ebx  - state
; ecx  - length
; edx  - 
; ebp  - jasm_t *
; esi  - stack index
; edi  - string
; [esp+4]  -
; [esp+8]  -
; [esp+12] -
; [esp+16] -
; 
;
; wstable: a table of whitespace chars to filter
; json_buffer: the start of the json buffer
; block_count (ebx): the number of chars left in the working block
; stack_index: the current level in the namespace stack
; json_ptr: a pointer to the current char in the json string
; json_len: the total length of the json string in the buffer
;
;
; States Bits:
; .newv - The parser has just found a new value
; .req? - The parser is now expecting a new array value or object key string
; .newk - The parser is expecting a new key string
; REQ?_STATE - 0x1
; 
;
; 0x5b - left square bracket   01011011
; 0x5d - right square bracket  01011101
; 0x7b - left curly brace      01111011
; 0x7d - right curly brace     01111101
; 0x2c - comma                 00101100
; 0x3a - colon                 00111010
; 0x22 - double quote          00100010
; 0x5c - backslash             01011100
; 0x66 - f (false)             01100110
; 0x74 - t (true)              01110100
; 0x6e - n (null)              01101110
;
; 0x09 - horizontal tab        00001001
; 0x0a - line feed             00001010
; 0x0d - carriage return       00001101
; 0x20 - space                 00100000
;
;*********************************************************************
internal_parse128:
    sub esp, 8   ; create space on the stack for locals

    ;test ebp[

    mov ebp, ecx
    ;movzx eax, word [ecx+PHASE_OFFSET]        ; eax = parser->phase
    mov eax, dword [ecx+PHASE_OFFSET]         ; eax = parser->phase
    add eax, .bgn                             ; add .bgn address to phase offset
    jmp eax                                   ; jump to phase address

    ;test [ecx+] 


    vmovdqu xmm3, oword [wstable]
    vmovdqu xmm4, oword [wstable+64]
    vmovdqu xmm5, oword [wstable+128]
    vmovdqu xmm6, oword [wstable+192]

    ;lea edi, [ecx+esi*4+NS_STACK_OFFSET]     ; current namespace pointer


    xor ebx, ebx                              ; set the state to zero

    ;find the first structure of the document
    .next_block:
    vmovdqu   xmm2, oword [edi]
    vpcmpeqb  xmm0, xmm2, xmm3 
    vpcmpeqb  xmm1, xmm2, xmm4
    vpor      xmm0, xmm0, xmm1
    vpcmpeqb  xmm1, xmm2, xmm5
    vpor      xmm0, xmm0, xmm1
    vpcmpeqb  xmm1, xmm2, xmm6
    vpor      xmm0, xmm0, xmm1
    vpmovmskb eax,  xmm0
    not       eax                        ; flip masked bits

    .next_char:
    bsf ecx, eax                     ; get next char
    jz .next_block
    ;add edi, 16 ; /32/64
    
    test 0xf, [edi+ecx]
    shr eax, cl                      ; remove bits before next char
    sub ebx, ecx                     ; decrement count by whitespace chars
    movzx eax, byte [edi+eax*1]      ; store the current char in a register
    mov eax, [jmptable+eax]
    add eax, internal_parse128
    jmp eax
    ;.bgn label that structure labels are offset from
        

    .com: ; a comma was found
    ; test if we're in an object then go look for a new key,
    ; else assume we're in an array, then go look for a new value
    .dqu: ; a double quote was found
    ;  if NODQU_BIT == true, then error
    ; else if OBJECT_BIT == true then create object key
    ; else create array string value
    ;bsf reg, reg  ; find next char in block
    ;jz next_block
    .com: ; TODO we should never come across a comma randomly in a document so this should be an error
    .col: ; TODO we should never come across a colon randomly in a document so this should be an error
    ; if COL_BIT == false, then error 
    ; else we've just created a new key, unset NODQU_BIT & COL_BIT
    .lsb:
    .bsl:
    .rsb:
    .fal:
    .nul:
    .tru:
    .lcb:
    .rcb:



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
    mov eax, [edi]                             ; skip whitespace
    add edi, [ebx+eax]
    sub ecx, [ebx+eax]                         ; decrement the length
    and eax, eax
    jnz short -10
    ;mov eax, .aov - .bgn; store the jmp address
    mov [ecx+PHASE_OFFSET], word .aov - .bgn; store the jmp address
    mov [ebp], eax
    ; call skipws
    ;add

    test byte [eax], 0x5d               ; if(*ptr == ']') 
    je .lns

.abv:
    mov eax, .abv - .bgn
    mov [ebp+0], eax
    ; call skipws
    ; validate value

	
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
    ;call .sws

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


;internal_parse256:





;internal_parse512:


[section .bss] ; data?

struc parser_state
	phase:   resb 1
endstruc



[section .data]


char_table db                                   \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0







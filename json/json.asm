
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

leaveNamespace:

; 

; struct parser_state {
; 	char 
;
; }


@parseJson@8:
	sub esp, 8   ; create space on the stack for locals


.arr_opt_val:

.arr_req_val:

.arr_end_val:
.obj_opt_key:
.obj_req_key:
.obj_end_key:
.obj_req_val:
.obj_end_val:

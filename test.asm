

ifndef X64

.model flat, stdcall 
.XMM
.686p

SYSCALL_NTCLOSE                    equ 001H
SYSCALL_NTTERMINATETHREAD          equ 002H
SYSCALL_NTTERMINATEPROCESS         equ 003H
SYSCALL_NTWRITEFILE                equ 004H
SYSCALL_NTREADFILE                 equ 005H
SYSCALL_NTCREATEPROCESS            equ 006H
SYSCALL_NTCREATETHREAD             equ 007H
SYSCALL_NTWRITEVIRTUALMEMORY       equ 008H
SYSCALL_NTREADVIRTUALMEMORY        equ 009H
SYSCALL_NTCREATEEVENT              equ 00AH
SYSCALL_NTCREATENAMEDPIPEFILE      equ 00BH
SYSCALL_NTALLOCATEVIRTUALMEMORY    equ 00CH
SYSCALL_NTFREEVIRTUALMEMORY        equ 00DH



;SYSCALL_NTCREATEIOCOMPLETION
;SYSCALL_NTOPENCOMPLETION
;SYSCALL_NTQUERYIOCOMPLETION
;SYSCALL_NTSETIOCOMPLETION
;SYSCALL_NTSETIOCOMPLETIONEX
;SYSCALL_NTREMOVEIOCOMPLETION
;SYSCALL_NTOPENPROCESS
;SYSCALL_NTGETCONTEXTTHREAD
;SYSCALL_NTDELAYEXECUTION
;SYSCALL_NTALERTTHREAD
;SYSCALL_NTCREATEPROCESSEX
;SYSCALL_NTWAITFORSINGLEOBJECT
;SYSCALL_NTCREATETIMER
;SYSCALL_NTCREATETIMER2
;SYSCALL_NTOPENTIMER
;SYSCALL_NTSETTIMER
;SYSCALL_NTCANCELTIMER
;SYSCALL_NTDUPLICATEOBJECT
;SYSCALL_NTDELETEFILE
;SYSCALL_NTOPENFILE
;SYSCALL_NTQUERYINFORMATIONPROCESS
;SYSCALL_NTQUERYSYSTEMINFORMATION
;SYSCALL_NTQUERYINFORMATIONFILE
;SYSCALL_NTCREATEDIRECTORYOBJECT
;SYSCALL_NTCREATEDIRECTORYOBJECTEX
;SYSCALL_NTQUERYDIRECTORYFILEEX



.data

comment ~
SystemCallTable DW \
\
\	; Windows Server 2008
\
\	; Windows 7
\
\	; Windows 8
\
\	; Windows 10
	018EH, 0023H,
~

.code



IFNDEF  _WIN64

voidptr_t typedef dword
regsize_t typedef dword
size_t    typedef dword

NtSystemCall equ sysenter

ELSE

voidptr_t typedef qword
regsize_t typedef qword
size_t    typedef qword

NtSystemCall equ syscall

ENDIF





comment ~
 Returns: Pointer to the current thread's TEB
~
IFNDEF _WIN64
ASSUME fs:nothing
NtCurrentTeb proc public
	mov eax, dword ptr fs:[18h]
	ret
NtCurrentTeb endp
ELSE
NtCurrentTeb proc public
	mov rax, qword ptr gs:[30h]
	ret
NtCurrentTeb endp
ENDIF


; NtAccessCheck
; NtWorkerFactoryWorkerReady
; NtAcceptConnetPort
; NtYieldExecution
; NtWriteVirtualMemory
; NtWriteRequestData
; NtWriteFileGather
; NtWriteFile
; NtWaitLowEventPair
; NtWaitHighEventPair
; NtWaitForWorkViaWorkerFactory
; NtWaitForSingleObject
; NtWaitForMultipleObjects32
; NtWaitForMultipleObjects
; NtWaitForKeyedEvent
; NtWaitForDebugEvent
; NtWaitForAlertByThreadId
; NtVdmControl
; NtUnsubscribeWnfStateChange
; NtUpdateWnfStateData
; NtUnmapViewOfSection
; NtUnmapViewOfSectionEx
; NtUnlockVirtualMemory
; NtUnlockFile
; NtUnloadKeyEx
; NtUnloadKey2
; NtUnloadKey
; NtUnloadDriver
; NtUmsThreadYield
; NtTranslateFilePath
; NtTraceEvent
; NtTraceControl
; NtThawTransactions
; NtThawRegistry
; NtTestAlert
; NtTerminateJobObject
; NtTerminateEnclave
; NtSystemDebugControl
; NtSuspendThread
; NtSuspendProcess
; NtSubscribeWnfStateChange
; NtStopProfile
; NtStartProfile
; NtSinglePhaseReject
; NtSignalAndWaitForSingleObject
; NtShutdownWorkerFactory
; NtShutdownSystem
; NtSetWnfProcessNotificationEvent
; NtSetVolumeInformationFile
; NtSetValueKey
; NtSetUuidSeed
; NtSetTimerEx



comment ~ ******************************************

NTSTATUS __stdcall NtClose(HANDLE);

	Windows 7:
	SP0: 50
	SP1: 50

	Windows 8:
	8.0: 372
	8.1: 377

	Windows10:
	1507: 384
	1511: 387
	1607: 389
	1703: 394
	1709: 397
	1803: 397
	1809: 397
	1903: 397
	1909: 397
	2004: 398  0x18e
	20H2: 398  0x18e

************************************************** ~

NtClose PROC PUBLIC

	
	mov eax, 018EH
	NtSystemCall
	ret

NtClose ENDP






comment ~ ******************************************

Sets the resolution of the system timer in the process context

NTSTATUS __stdcall NtSetTimerResolution(
	IN  ULONG   DesiredResolution,
	IN  BOOLEAN SetResolution,
	OUT PULONG  CurrentResolution);

	Windows10: 53 (0x35)

************************************************** ~

NtSetTimerResolution PROC PUBLIC

	mov eax, 035h
	NtSystemCall
	ret

NtSetTimerResolution ENDP





comment ~ ********************************************

NTSTATUS __stdcall NtSetTimerEx(
	HANDLE TimerHandle,
	TIMER_SET_INFORMATION_CLASS TimerSetInfoClass,
	void *TimerSetInfo,
	unsigned long TimerSetInfoClass);

	Windows10: 54 (0x36)

**************************************************** ~

NtSetTimerEx PROC PUBLIC

	mov eax, 036h
	NtSystemCall
	ret

NtSetTimerEx ENDP






comment ~ *************************************

NTSTATUS __stdcall NtCreateIoCompletion(
	void **IoCompletionHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	unsigned long Count);

********************************************* ~
IFNDEF _WIN64
NtCreateIoCompletion2 proc public\
	IoCompletionHandle :voidptr_t,
	DesiredAccess      :size_t,
	ObjectAttributes   :voidptr_t,
	Count              :size_t

	push dword ptr [esp+16]
	push dword ptr [esp+12]
	push dword ptr [esp+8]
	push dword ptr [esp+4]
	mov eax, SYSCALL_NTCREATEIOCOMPLETION
	NtSystemCall
	add esp, 16
	ret
NtCreateIoCompletion2 endp
ELSE
NtCreateIoCompletion2 proc public\
	IoCompletionHandle :voidptr_t,
	DesiredAccess      :size_t,
	ObjectAttributs    :voidptr_t,
	Count              :size_t

	push dword ptr [esp+32]
	push dword ptr [esp+24]
	push dword ptr [esp+16]
	push dword ptr [esp+8]
	mov eax, SYSCALL_NTCREATEIOCOMPLETION
	NtSystemCall
	add esp, 32
	ret
NtCreateIoCompletion2 endp 
ENDIF




comment ~ *****************************************

Causes a process to terminate and all child threads

unsigned long __stdcall NtTerminateProcess(
	void *ProcessHandle, 
	unsigned long ExitStatus);

	Windows Server 2008 : 334
	Windows7            : 370
	Windows8            : 35
	Windows10           : 36

************************************************* ~

NtTerminateProcess proc public\
	ProcessHandle  :voidptr_t,
	ExitStatus     :size_t

	mov eax, 024h
	NtSystemCall
	ret
NtTerminateProcess endp







comment ~ ****************************************************************

Causes a thread to terminate

NTSTATUS __stdcall NtTerminateThread(
	HANDLE ThreadHandle,
	NTSTATUS ExitStatus);

	Windows Server 2008: 335
	Windows7:  371
	Windows8:  34
	Windows10: 35

************************************************************************ ~

NtTerminateThread PROC PUBLIC\
	ThreadHandle   :voidptr_t,
	ExitStatus     :size_t

	mov eax, 023h
	NtSystemCall
	ret

NtTerminateThread ENDP




COMMENT ~ ******************************************************************
Retrieves information about the specified process.
PTR ProcessHandle:
	A handle to the process for which information is to be retrieved.
DWORD ProcessInformationClass:
	The type of processinformation to be retrieved.
PTR ProcessInformation:
	Buffer to receive information, The data struct supplied
	here depends on the ProcessInformationClass parameter
DWORD ProcessInformationLength:
	Size of the buffer pointed to by ProcessInformation
DWORD PTR ReturnLength:
	Pointer to value to receives the size of the requested information.
	This value should match the ProcessInformationLenth...maybe?
RETURN: NtStatus
************************************************************************** ~

NtQueryInformationProcess2 PROC PUBLIC\
	ProcessHandle            :DWORD,
	ProcessInformationClass  :DWORD,
	ProcessInformation       :DWORD,
	ProcessInformationLength :DWORD,
	ReturnLength             :DWORD

	push ebp
	mov ebp, esp

	mov eax, 0b0h
	NtSystemCall

	pop ebp
	retn

NtQueryInformationProcess2 ENDP 






ASSUME fs:error



;ELSE ;Code for .64
;.code


ENDIF


end

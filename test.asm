

;ifndef X64

;.model flat, stdcall 
;.XMM
;.686p

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



[section .data]

; SystemCallTable DW \
;
;	; Windows Server 2008
;
;	; Windows 7
;
;	; Windows 8
;
;	; Windows 10
;	018EH, 0023H,



[section .text]


%ifidn __?OUTPUT_FORMAT?__, win32

;voidptr_t typedef dword
;regsize_t typedef dword
;size_t    typedef dword

%define NtSystemCall sysenter
;NtSystemCall equ sysenter

%elifidn __?OUTPUT_FORMAT?__, win64

voidptr_t typedef qword
regsize_t typedef qword
size_t    typedef qword

%define NySystemCall syscall
;NtSystemCall equ syscall

%endif



global _NtCurrentTeb@0
global _NtCurrentPeb@0



; Returns: Pointer to the current thread's TEB

_NtCurrentTeb@0 :
%ifidn __?OUTPUT_FORMAT?__, win32
	mov eax, dword [fs:0x18]
	add esp, 4
	jmp [esp-4]
%elifidn __?OUTPUT_FORMAT?__, win64
	mov rax, qword [gs:0x30]
	add esp, 8
	jmp [esp-8]
%endif



; Returns Pointer to the PEB of the current process

_NtCurrentPeb@0:
%ifidn __?OUTPUT_FORMAT?__, win32
	mov eax, dword [fs:0x30]
	add esp, 4
	jmp [esp-4]
%elifidn __?OUTPUT_FORMAT?__, win64
	mov rax, qword [gs:0x60]
	add esp, 8
	jmp [esp-8]
%endif


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




; *****************************************************
;NTSTATUS __stdcall NtClose(HANDLE);
;
;	Windows 7:
;	SP0: 50
;	SP1: 50
;
;	Windows 8:
;	8.0: 372
;	8.1: 377
;
;	Windows10:
;	1507: 384
;	1511: 387
;	1607: 389
;	1703: 394
;	1709: 397
;	1803: 397
;	1809: 397
;	1903: 397
;	1909: 397
;	2004: 398  0x18e
;	20H2: 398  0x18e
; Handle [esp+4]
; *****************************************************
_NtClose@4 :
	mov eax, 0x18
	mov edx, esp
	NtSystemCall
	ret





; *****************************************************
; Sets the resolution of the system timer in the process context
;
; NTSTATUS __stdcall NtSetTimerResolution(
;	IN  ULONG   DesiredResolution,
;	IN  BOOLEAN SetResolution,
;	OUT PULONG  CurrentResolution);
;
;	Windows10: 53 (0x35)
;
; *****************************************************
_NtSetTimerResolution@0 :
	mov eax, 0x35 
	mov edx, esp
	NtSystemCall
	ret




; *****************************************************
;NTSTATUS __stdcall NtSetTimerEx(
;	HANDLE TimerHandle,
;	TIMER_SET_INFORMATION_CLASS TimerSetInfoClass,
;	void *TimerSetInfo,
;	unsigned long TimerSetInfoClass);
;
;	Windows10: 54 (0x36)
; *****************************************************

_NtSetTimerEx@0 :
	mov eax, 0x36
	mov edx, esp
	NtSystemCall
	ret




; *****************************************************
;NTSTATUS __stdcall NtCreateIoCompletion(
;	void **IoCompletionHandle,
;	ACCESS_MASK DesiredAccess,
;	OBJECT_ATTRIBUTES *ObjectAttributes,
;	unsigned long Count);
;
; IoCompletionHandle = [esp+4]
; DesiredAccess      = [esp+8]
; ObjectAttributes   = [esp+12]
; Count              = [esp+16]
; *****************************************************

_NtCreateIoCompletion2@16 :
;	mov eax, SYSCALL_NTCREATEIOCOMPLETION
	mov edx, esp
	NtSystemCall
	add esp, 16
	ret




; ***************************************************
;
; Causes a process to terminate and all child threads
;
; unsigned long __stdcall NtTerminateProcess(
;	void *ProcessHandle, 
;	unsigned long ExitStatus);
;
;	Windows Server 2008 : 334
;	Windows7            : 370
;	Windows8            : 35
;	Windows10           : 36
;
; ProcessHandle  [esp+4]
; ExitStatus     [esp+8]
;
; *************************************************

_NtTerminateProcess@8 :
	mov eax, 0x24 
	mov edx, esp
	NtSystemCall
	ret





; ****************************************************************
;
; Causes a thread to terminate
;
;
; NTSTATUS __stdcall NtTerminateThread(
;	HANDLE ThreadHandle,
;	NTSTATUS ExitStatus);
;
;	Windows Server 2008: 335
;	Windows7:  371
;	Windows8:  34
;	Windows10: 35
;
; ThreadHandle [esp+4]
; ExitStatus   [esp+8]
;
; ***************************************************************
_NtTerminateThread@8 :
	mov eax, 0x23
	mov edx, esp
	NtSystemCall
	ret




; ****************************************************************
;Retrieves information about the specified process.
;PTR ProcessHandle: [esp+4]
;	A handle to the process for which information is to be retrieved.
;DWORD ProcessInformationClass: [esp+8]
;	The type of processinformation to be retrieved.
;PTR ProcessInformation: [esp+12]
;	Buffer to receive information, The data struct supplied
;	here depends on the ProcessInformationClass parameter
;DWORD ProcessInformationLength: [esp+16]
;	Size of the buffer pointed to by ProcessInformation
;DWORD PTR ReturnLength: [esp+20]
;	Pointer to value to receives the size of the requested information.
;	This value should match the ProcessInformationLenth...maybe?
;RETURN: NtStatus
; ****************************************************************


_NtQueryInformationProcess2@20 :
	mov eax, 0xb0
	mov edx, esp
	NtSystemCall
	ret


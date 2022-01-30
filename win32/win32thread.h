typedef unsigned long (__stdcall *PUSER_THREAD_START_ROUTINE)(void *Argument);

typedef struct _INITIAL_TEB {
	struct {
	// A pointer to the base of a fixed-size stack.
		void *Base;

	// A pointer to the limit (that is, top) of a fixed-size stack.
		void *Limit;
	} FixedStack;

	struct {
	// A pointer to the base of the committed memory of an expandable stack
		void *Base;
	// A pointer to the limit (that is, top) of the committed memory of an
	// expandable stack
		void *Limit;

	// A pointer to the bottom of the reserved memory of an expandable stack.
		void *ReservedBase;
	} ExpandableStack;
	void *Next;
	void *Reserved[2];
} INITIAL_TEB;



// Format of data for (F)XSAVE/(F)XRSTOR instruction
typedef struct _XSAVE_FORMAT {
	WORD ControlWord;
	WORD StatusWord;
	BYTE TagWord;
	BYTE Reserved1;
	WORD ErrorOpcode;
	DWORD ErrorOffset;
	WORD ErrorSelector;
	WORD Reserved2;
	DWORD DataOffset;
	WORD DataSelector;
	WORD Reserved3;
	DWORD MxCsr;
	DWORD MxCsr_Mask;
	M128A FloatRegisters[8];
#if defined(_WIN64)
	M128A XmmRegisters[16];
	BYTE Reserved4[96];
#else
	M128A XmmRegisters[8];
	BYTE Reserved4[224];
#endif
} XSAVE_FORMAT, *PXSAVE_FORMAT;

typedef XSAVE_FORMAT XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;


#define KERNEL_CS         0x08
#define KERNEL_DS         0x10
#define USER_CS           0x1b
#define USER_DS           0x23
#define TSS_SELECTOR      0x28 /* Task State Segment */
#define PCR_SELECTOR      0x30 /* Processor Control Region */
#define TEB_SELECTOR      0x3b /* Thread Environment Block */
#define RESERVED_SELECTOR 0x40
#define LDT_SELECTOR      0x48 /* Local Descriptor Table */
#define TRAP_TSS_SELECTOR 0x50




#define CONTEXT_CONTROL            0x00010001
#define CONTEXT_INTEGER            0x00010002
#define CONTEXT_SEGMENTS           0x00010004
#define CONTEXT_FLOATING_POINT     0x00010008
#define CONTEXT_DEBUG_REGISTERS    0x00010010
#define CONTEXT_EXTENDED_REGISTERS 0x00010020


typedef struct _X86_64_CONTEXT {

	// Register parameter home addresses
	QWORD P1Home;
	QWORD P2Home;
	QWORD P3Home;
	QWORD P4Home;
	QWORD P5Home;
	QWORD P6Home;

	// Control Flags
	DWORD   ContextFlags;
	DWORD   MxCsr;

	// Segment Registers and processor flags
	WORD    SegCs;
	WORD    SegDs;
	WORD    SegEs;
	WORD    SegFs;
	WORD    SegGs;
	WORD    SegSs;
	DWORD   EFlags;

	// Debug registers
	QWORD Dr0;
	QWORD Dr1;
	QWORD Dr2;
	QWORD Dr3;
	QWORD Dr6;
	QWORD Dr7;

	// Integer registers
	QWORD Rax;
	QWORD Rcx;
	QWORD Rdx;
	QWORD Rbx;
	QWORD Rsp;
	QWORD Rbp;
	QWORD Rsi;
	QWORD Rdi;
	QWORD R8;
	QWORD R9;
	QWORD R10;
	QWORD R11;
	QWORD R12;
	QWORD R13;
	QWORD R14;
	QWORD R15;

	// Program counter
	QWORD Rip;

	// Floating point state
	union {
		XMM_SAVE_AREA32 FltSave;
		struct {
			M128A Header[2];	
			M128A Legacy[8];
			M128A Xmm0;
			M128A Xmm1;
			M128A Xmm2;
			M128A Xmm3;
			M128A Xmm4;
			M128A Xmm5;
			M128A Xmm6;
			M128A Xmm7;
			M128A Xmm8;
			M128A Xmm9;
			M128A Xmm10;
			M128A Xmm11;
			M128A Xmm12;
			M128A Xmm13;
			M128A Xmm14;
			M128A Xmm15;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	// Vector registers
	M128A VectorRegister[26];
	QWORD VectorControl;


	// Special debug control registers
	QWORD DebugControl;
	QWORD LastBranchToRip;
	QWORD LastBranchFromRip;
	QWORD LastExceptionToRip;
	QWORD LastExceptionFromRip;

} X86_64_CONTEXT;


#define WOW64_SIZE_OF_80387_REGISTERS     80
#define WOW64_MAXIMUM_SUPPORTED_EXTENSION 512


typedef struct _WOW64_FLOATING_SAVE_AREA {
	DWORD ControlWord;
	DWORD StatusWord;
	DWORD TagWord;
	DWORD ErrorOffset;
	DWORD ErrorSelector;
	DWORD DataOffset;
	DWORD DataSelector;
	BYTE  RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
	DWORD Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA;


typedef struct _X86_32_CONTEXT {

	DWORD ContextFlags;
	
	DWORD Dr0;
	DWORD Dr1;
	DWORD Dr2;
	DWORD Dr3;
	DWORD Dr6;
	DWORD Dr7;

	WOW64_FLOATING_SAVE_AREA FloatSave;

	DWORD SegGs;
	DWORD SegFs;
	DWORD SegEs;
	DWORD SegDs;

	/*
	This section is specified/returned if the ContextFlags
	word contains the flag CONTEXT_CONTROL
	*/

	DWORD Edi;
	DWORD Esi;
	DWORD Ebx;
	DWORD Edx;
	DWORD Ecx;
	DWORD Eax;


	DWORD Ebp;
	DWORD Eip;
	DWORD SegCs;
	DWORD EFlags;
	DWORD Esp;
	DWORD SegSs;

	BYTE ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];

} X86_32_CONTEXT;


typedef struct _ARM64_CONTEXT {
	DWORD ContextFlags;
} ARM64_CONTEXT;


typedef union _CONTEXT {
	X86_32_CONTEXT x86;
	X86_64_CONTEXT x64;
} CONTEXT;



typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
	unsigned long Flags;
	const char *FrameName;
} TEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT_EX
{
	TEB_ACTIVE_FRAME_CONTEXT BasicContext;
	const char *SourceLocation;
} TEB_ACTIVE_FRAME_CONTEXT_EX;


typedef struct _TEB_ACTIVE_FRAME
{
	unsigned long Flags;
	struct _TEB_ACTIVE_FRAME *Previous;
	struct _TEB_ACTIVE_FRAME_CONTEXT *Context;
} TEB_ACTIVE_FRAME;


typedef enum _EXCEPTION_DISPOSITION
{
	ExceptionContinueExecution,
	ExceptionContinueSearch,
	ExceptionNestedException,
	ExceptionCollidedUnwind
} EXCEPTION_DISPOSITION;


typedef struct _EXCEPTION_REGISTRATION_RECORD
{
	struct _EXCEPTION_REGISTRATION_RECORD *Next;
	EXCEPTION_DISPOSITION * Handler;
} EXCEPTION_REGISTRATION_RECORD;


typedef struct _NT_TIB
{
	EXCEPTION_REGISTRATION_RECORD *ExceptionList;
	void *StackBase;
	void *StackLimit;
	void *SubSystemTib;
	union
	{
		void *FiberData;
		unsigned long Version;
	};
	void *ArbitraryUserPointer;
	struct _NT_TIB *Tib;
} NT_TIB;



typedef struct _TEB
{
	NT_TIB NtTib;
	void *EnvironmentPointer;
	void *ProcessId;
	void *ThreadId;
	void *ActiveRpcHandle;
	void *ThreadLocalStoragePointer;
	struct _PEB *ProcessEnvironmentBlock;
	unsigned int LastErrorValue; // 32 bits on x64
	unsigned int CountOfOwnedCriticalSections; // 32 bits on x64
	void *CsrClientThread;
	void *Win32ThreadInfo;
	unsigned long Win32ClientInfo[0x1f];
	void *WOW32Reserved; //WOW64Reserved Contains pointer to FastSysCall in WOW64
	unsigned int CurrentLocale;
	unsigned int FpSoftwareStatusRegister;
	char SystemReserved1[0x58];
	void *EThread; // TODO Fill out this struct
	char SystemReserved2[0x7c];
	unsigned long ExceptionCode;
	char ActivationContextStack[0x12];
	char SpareBytes1[0x18];
	char SystemReserved3[0x28];
	char GdiTebBatch[0x4e0];
	void *GdiRgn;
	void *GdiPen;
	void *GdiBrush;
	void *RealProcessId;
	void *RealThreadId;
	void *GdiCachedProcessHandle;
	unsigned int GdiClientPid; // 32 bits on x64
	unsigned int GdiClientTid; // 32 bits on x64
	void *GdiThreadLocaleInfo;

#if defined(NOMAKE_32BIT)
	char UserReserved[0x14];
#elif defined(NOMAKE_64BIT)
	char UserReserved[0x18];
#endif

	void *GlDispatchTable[0x118];
	void *GlReserved1[0x1A];
	void *GlReserved2;
	void *GlSectionInfo;
	void *GlSection;
	void *GlTable;
	void *GlCurrentRC;
	void *GlContext;
	unsigned long LastStatusValue; //32 on x86; 64 on x64
	UNICODE_STRING StaticUnicodeString; // used by advapi32
	wchar_t StaticUnicodeBuffer[0x105];
	void *DeallocationStack;
	void *TlsSlots[0x40];
	LIST_ENTRY TlsLinks;
	void *Vdm;
	void *ReservedForNtRpc;
	void *DbgSsReserved[0x2];
	unsigned long HardErrorDisabled;
	void *Instrumentation[0x10];
	void *WinSockData;
	unsigned int GdiBatchCount; // 32 bits on x64
	unsigned int Spare2;
	unsigned long GuaranteedStackBytes;
	void *ReservedForPerf;
	void *ReservedForOle;
	unsigned long WaitingOnLoaderLock;
	void *StackCommit;
	void *StackCommitMax;
	void *StackReserved;
	void **TlsExpansionSlots;
#if defined(NOMAKE_64BIT)
	void *DeallocationBStore;
	void *BStoreLimit;
#endif
	unsigned int ImpersonationLocale;
	unsigned int IsImpersonating;
	void *NlsCache;
	void *ShimData;
	unsigned long HeapVirtualAffiinity;
	void *CurrentTransactionHandle;
	TEB_ACTIVE_FRAME *ActiveFrame;
	void **FlsSlots;
} TEB, TIB;



TEB * __stdcall NtCurrentTeb(void);


unsigned long __stdcall NtGetContextThread(
	void *ThreadHandle,
	CONTEXT *ThreadContext);




unsigned long __stdcall NtCreateThread(
	void **ThreadHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	void *ProcessHandle,
	CLIENT_ID *ClientId,
	CONTEXT *ThreadContext,
	INITIAL_TEB *InitialTeb,
	bool CreateSuspend);



unsigned long __stdcall NtCreateThreadEx(
	void **ThreadHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	void *ProcessHandle,
	PUSER_THREAD_START_ROUTINE StartRoutine,
	void *Argument,
	unsigned long CreateFlags,
	size_t StackZeroBits,
	size_t StackCommitSize,
	size_t StackReserveSize,
	PS_ATTRIBUTE_LIST *AttributeList);



#define STACK_SIZE_PARAM_IS_A_RESERVATION  0x00010000



/* Thread Access Rights */

/**
 *  Required to terminate a thread using TerminateThread
*/
#define THREAD_TERMINATE                  0x0001

/**
 * Required to suspend or resume a thread
*/
#define THREAD_SUSPEND_RESUME             0x0002


/**
 * Required to alert a thread
*/
#define THREAD_ALERT                      0x0004

/**
 * Required to read the context of a thread using GetThreadContext
*/
#define THREAD_GET_CONTEXT                0x0008

/**
 * Required to write the context of a thread using SetThreadContext
*/
#define THREAD_SET_CONTEXT                0x0010

/**
 * Required to set certain information in the thread object.
*/
#define THREAD_SET_INFORMATION            0x0020

/**
 * Required to read certain information from the thread object,
 * such as the exit code
*/
#define THREAD_QUERY_INFORMATION          0x0040

/**
 * Required to set the impersonation token for a thread using SetThreadToken
*/
#define THREAD_SET_THREAD_TOKEN           0x0080

/**
 * Required to use a thread's security information directly without
 * calling it by using a communication mechanism that provides
 * impersonation services.
*/
#define THREAD_IMPERSONATE                0x0100

/**
 * Required for a server thread that impersonates a client.
*/
#define THREAD_DIRECT_IMPERSONATION       0x0200

/**
 * Required to set certain information in the thread object. A handle that
 * has the THREAD_SET_INFORMATION access right is automatically granted
 * THREAD_SET_LIMITED_INFORMATION. Not supported in Windows Server 2003
 * and Windows XP.
*/
#define THREAD_SET_LIMITED_INFORMATION    0x0400

/**
 * Required to read certain information from the thread objects, A handle
 * that has the THREAD_QUERY_INFORMATION access right is automatically
 * granted THREAD_QUERY_LIMITED_INFORMATION. Not supported in Windows
 * Server 2003 and Windows XP.
*/
#define THREAD_QUERY_LIMITED_INFORMATION  0x0800



/* Thread Create Flags */
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED         0x0001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH       0x0002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER       0x0004
#define THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR  0x0010
#define THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET   0x0020
#define THREAD_CREATE_FLAGS_INITIAL_THREAD           0x0080



/**
 * Puts the thread into an alertable or nonalertable wait state
 * for a specified interval
 *
 * Alertable - Specifes TRUE if the wait is alertable. Lower-level drivers should
 * specify FALSE.
 *
 * DelayInterval - Specifies the absolute or relative time, in units of 100 nanoseconds,
 * for which the wait is to occur. A negative value indicates relative time. Absolute
 * expiration time track any changes in system time; relative expiration times are not
 * affected by system time changes.
 */
unsigned long __stdcall NtDelayExecution
	(bool Alertable,
	LARGE_INTEGER *DelayInterval);


unsigned long __stdcall NtAlertThread(void *ThreadHandle);


unsigned long __stdcall NtResumeThread
	(void *ThreadHandle,
	unsigned long *SuspendCount);




unsigned long __stdcall NtTerminateThread(
	void *Handle,
	unsigned long ExitStatus);


inline void * __stdcall NtCurrentThread()
{
	return (void*)0xfffffffe;
}

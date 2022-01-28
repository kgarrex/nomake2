

inline void * __stdcall NtCurrentProcess()
{
	return (void*)0xffffffff;
}


typedef struct _PEB_FREE_BLOCK
{
	struct _PEB_FREE_BLOCK *Next;
	unsigned long Size;
} PEB_FREE_BLOCK;



typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	short Flags;
	short Length;
	unsigned long TimeStamp;
	union {
		ANSI_STRING DosPathA;
		UNICODE_STRING DosPathW;
	};
} RTL_DRIVE_LETTER_CURDIR;



/* RTL_USER_PROCESS_PARAMETERS flags */
#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED     0x00001
#define RTL_USER_PROCESS_PROFILE_USER          0x00002
#define RTL_USER_PROCESS_PROFILE_KERNEL        0x00004
#define RTL_USER_PROCESS_PROFILE_SERVER        0x00008
#define RTL_USER_PROCESS_RESERVE_1MB           0x00020
#define RTL_USER_PROCESS_RESERVE_16MB          0x00040
#define RTL_USER_PROCESS_CASE_SENSITIVE        0x00080
#define RTL_USER_PROCESS_DISABLE_HEAP_DECOMMIT 0x00100
#define RTL_USER_PROCESS_PARAMETERS_PROCESS_OR_1 0x00200
#define RTL_USER_PROCESS_PARAMETERS_PROCESS_OR_2 0x00400  // check on this!
#define RTL_USER_PROCESS_DLL_REDIRECTION_LOCAL 0x01000
#define RTL_USER_PROCESS_PARAMETERS_PRIVATE_DLL_PATH      0x01000 // check on this!
#define RTL_USER_PROCESS_APP_MANIFEST_PRESENT  0x02000
#define RTL_USER_PROCESS_PARAMETERS_LOCAL_DLL_PATH        0x02000 // check on this!
#define RTL_USER_PROCESS_IMAGE_KEY_MISSING     0x04000
#define RTL_USER_PROCESS_OPTIN_PROCESS         0x20000


typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	unsigned long MaximumLength;
	unsigned long Length;
	unsigned long Flags;
	unsigned long DebugFlags;
/**
 * HWND to console window associated with process (if any).
*/
	void *ConsoleHandle;
	unsigned long ConsoleFlags;
	void *StdInputHandle;
	void *StdOutputHandle;
	void *StdErrorHandle;
	UNICODE_STRING CurrentDirectoryPath;
	void *CurrentDirectoryHandle;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	wchar_t *Environment; // this field is required else you get ntstatus 0xc000000d!!
	unsigned long StartingX;
	unsigned long StartingY;
	unsigned long Width;
	unsigned long Height;
	unsigned long CharWidth;
	unsigned long CharHeight;
	unsigned long ConsoleTextAttributes;
	unsigned long WindowFlags;
	unsigned long ShowWindowFlags;
	UNICODE_STRING WindowsTitle;
	UNICODE_STRING DesktopName;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DlCurrentDirectory[0x20];
	size_t EnvironmentSize;
	size_t EnvironmentVersion;
} RTL_USER_PROCESS_PARAMETERS;




typedef struct _PEB_LDR_DATA
{
	char Reserved1[8];
	void *Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA;





typedef struct _PEB
{
	char InheritedAddressSpace;
	char ReadImageFileExecOptions;
	char BeingDebugged;
	char SpareBool;
	void *Mutant;
	void *ImageBaseAddress;
	PEB_LDR_DATA * Ldr;
	RTL_USER_PROCESS_PARAMETERS * ProcessParameters;
	void *SubSystemData;
	void *ProcessHeap;
	RTL_CRITICAL_SECTION *FastPebLock;
	void *FastPebLockRoutine;
	void *FastPebUnlockRoutine;
	unsigned long EnvironmentUpdateCount;
	void *KernelCallbackTable;
	unsigned long SystemReserved[1];
	unsigned int ExecuteOptions:2;
	unsigned int SpareBits:30;
	PEB_FREE_BLOCK *FreeList;
	unsigned long TlsExpansionCounter;
	void *TlsBitMap;
	unsigned long TlsBitmapBits[2];
	void *ReadOnlySharedMemoryBase;
	void *ReadOnlySharedMemoryHeap;
	void **ReadOnlyStaticServerData;
	void *AnsiCodePageData;
	void *OemCodePageData;
	void *UnicodeCaseTableData;
	unsigned int NumberOfProcessors;
	unsigned int NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	unsigned long HeapSegmentReserve;
	unsigned long HeapSegmentCommit;
	unsigned long HeapDeCommitTotalFreeThreshold;
	unsigned long HeapDeCommitFreeBlockThreshold;
	unsigned long NumberOfHeaps;
	unsigned long MaximumNumberOfHeaps;
	void **ProcessHeaps;
	void *GdiSharedHandleTable;
	void *ProcessStarterHelper;
	unsigned long GdiDCAttributeList;
	void *LoaderLock;
	unsigned long OSMajorVersion;
	unsigned long OSMinorVersion;
	unsigned short OSBuildNumber;
	unsigned short OSCSDVersion;
	unsigned long OSPlatformId;
	unsigned long ImageSubsystem;
	unsigned long ImageSubsystemMajorVersion;
	unsigned long ImageSubsystemMinorVersion;
	unsigned long ImageProcessAffinityMask;
	unsigned long GdiHandleBuffer[34];
	void (*PostProcessInitRoutine)();
	void *TlsExpansionBitmap;
	unsigned long TlsExpansionBitmapBits[32];
	unsigned long SessionId;
	LARGE_INTEGER AppCompatFlags;
	LARGE_INTEGER AppCompatFlagsUser;
	void *ShimData;
	void *AppCompatInfo;
	UNICODE_STRING CSDVersion;
	void *ActivationContextData;
	void *ProcessAssemblyStorageMap;
	void *SystemDefaultActivationContextData;
	void *SystemAssemblyStorageMap;
	unsigned long MinimumStackCommit;
} PEB;



typedef enum _PROCESS_INFORMATION_CLASS
{
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName                = 0x1b,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination           = 0x1d,
	ProcessDebugObjectHandle            = 0x1e,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessResourceManagment,
	ProcessCookie,
	ProcessImageInformation,
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback,
	ProcessThreadStackAllocation,
	ProcessWorkingSetWatchEx,
	ProcessImageFileNameWin32,
	ProcessImageFileMapping,
	ProcessAffinityUpdateMode,
	ProcessMemoryAllocationMode,
	ProcessGroupInformation,
	ProcessTokenVirtualizationEnabled,
	ProcessConsoleHostProcess,
	ProcessWindowInformation,
	ProcessHandleInformation,
	ProcessMitigationPolicy,
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode,
	ProcessKeepAliveCount,
	ProcessRevokeFileHandles,
	ProcessWorkingSetControl,
	ProcessHandleTable,
	ProcessCheckStackExtentsMode,
	ProcessCommandLineInformation,
	ProcessProtectionInformation,
	ProcessMemoryExhaustion,
	ProcessFaultInformation,
	ProcessTelemetryIdInformation,
	ProcessCommitReleaseInformation,
	ProcessDefaultCpuSetsInformation,
	ProcessAllowedCpuSetsInformation,
	ProcessSubsystemProcess,
	ProcessJobMemoryInformation,
	ProcessInPrivate,
	ProcessRaiseUMExceptionOnInvalidHandleClose,
	ProcessIumChallengeResponse,
	ProcessChildProcessInformation,
	ProcessHighGraphicsPriorityInformation,
	ProcessSubsystemInformation,
	ProcessEnergyValues,
	ProcessActivityThrottleState,
	ProcessActivityThrottlePolicy,
	ProcessWin32kSyscallFilterInformation,
	ProcessDisableSystemAllowedCpuSets,
	ProcessWakeInformation,
	ProcessEnergyTrackingState,
	ProcessManageWritesToExecutableMemory,
	ProcessCaptureTrustletLiveDump,
	ProcessTelemetryCoverage,
	ProcessEnclaveInformation,
	ProcessEnableReadWriteVmLogging,
	ProcessUptimeInformation,
	ProcessImageSection,
	ProcessDebugAuthInformation,
	ProcessSystemResourceManagement,
	ProcessSequenceNumber,
	ProcessLoaderDetour,
	ProcessSecurityDomainsInformation,
	ProcessEnableLogging,
	ProcessLeapSecondInformation,
	ProcessFiberShadowStackAllocation,
	ProcessFreeFiberShadowStackAllocation    = 0x63,
} PROCESS_INFORMATION_CLASS;


typedef struct _PROCESS_BASIC_INFORMATION
{
	unsigned long ExitStatus;
	PEB * PebBaseAddress;
	unsigned long AffinityMask;
	long BasePriority;
	unsigned long UniqueProcessId;

/**
 * Can be cast to a DWORD and contains a unique identifier for the
 * parent process.
*/
	unsigned long InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;


typedef struct _PROCESS_EXCEPTION_PORT
{
	void *ExceptionPortHandle;
	unsigned long StateFlags;
} PROCESS_EXCEPTION_PORT;


typedef struct _PROCESS_ACCESS_INFORMATION
{
	void *Token;
	void *Thread;
} PROCESS_ACCESS_INFORMATION;



typedef struct _PROCESS_DEVICEMAP_INFORMATION
{
	union
	{
		struct
		{
			void *DirectoryHandle;
		} Set;
		struct
		{
			unsigned long DriveMap;
			unsigned char DriveType[32];
		} Query;
	};
} PROCESS_DEVICEMAP_INFORMATION;






typedef enum _PS_CREATE_STATE {
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName,
	PsCreateSuccess,
	PsCreateMaximumStates
} PS_CREATE_STATE;


struct InitialState {
	union {
		unsigned long InitFlags;	
		struct {
			unsigned char WriteOutputOnExit:1;
			unsigned char DetectManifest:1;
			unsigned char IFEOSkipDebugger:1;
			unsigned char IFEODoNotPropagateKeyState:1;
			unsigned char SpareBits1:4;
			unsigned char SpareBits2:8;
			unsigned short ProhibitedImageCharacteristics:16;
		};
	};
	ACCESS_MASK AdditionalFileAccess;
};


struct FailOnSectionCreate {
	void *FileHandle;
};


struct FailExeFormat {
	unsigned short DllCharacterstics;
};

struct FailExeName {
	void *IFEOKey;
};


struct CreateSuccess {
	union {
		unsigned long OutputFlags;
		struct {
			unsigned char ProtectedProcess:1;
			unsigned char AddressSpaceOverride:1;
			unsigned char DevOverrideEnabled:1;
			unsigned char ManifestDetected:1;	
			unsigned char ProtectedProcessLight:1;
			unsigned char SpareBits1:3;
			unsigned char SpareBits2:8;
			unsigned short SpareBits:16;
		};
	};
	void *FileHandle;
	void *SectionHandle;
	unsigned long long UserProcessParametersaNative;
	unsigned long UserProcessParametersWow64;
	unsigned long CurrentParametersFlags;
	unsigned long long PebAddressNative;
	unsigned long PebAddressWow64;
	unsigned long long ManifestAddress;
	unsigned long ManifestSize;
};

typedef struct _PS_CREATE_INFO {
	size_t Size;
	PS_CREATE_STATE State;

	union {
		struct InitialState InitState;
		struct FailOnSectionCreate SectionCreate;
		struct FailExeFormat ExeFormat;
		struct FailExeName ExeName;
		struct CreateSuccess CreateSuccess;
	};
} PS_CREATE_INFO;


typedef enum _PS_ATTRIBUTE_ENUM {
	PsAttributeParentProcess,  // in HANDLE
	PsAttributeDebugPort,      // in HANDLE
	PsAttributeToken,          // in HANDLE
	PsAttributeClientId,       // out CLIENT_ID *
	PsAttributeTebAddress,     // out TEB **
	PsAttributeImageName,      // in wchar_t *
	PsAttributeImageInfo,      // out SECTION_IMAGE_INFORMATION
	PsAttributeMemoryReserve,  // in PS_MEMORY_RESERVE
	PsAttributePriorityClass,  // in unsigned char
	PsAttributeErrorMode,      // in unsigned long
	PsAttributeStdHandleInfo,  // 10, in PS_STD_HANDLE_INFO
	PsAttributeHandleList,     // in HANDLE *
	PsAttributeGroupAffinity,  // in GROUP_AFFINITY *
	PsAttributePreferredNode,  // in unsigned short *
	PsAttributeIdealProcessor, // in PROCESSOR_NUMBER *
	PsAttributeUmsThread,      // ? in UMS_CREATE_THREAD_ATTRIBUTES *
	PsAttributeMitigationOptions, // in unsigned char
	PsAttributeProtectionLevel,
	PsAttributeSecureProcess, // since THRESHOLD
	PsAttributeJobList,
	PsAttributeChildProcessPolicy, // since THRESHOLD2
	PsAttributeAllApplicationPackagesPolicy, // since REDSTONE
	PsAttributeWin32kFilter,
	PsAttributeSafeOpenPromptOriginClaim,
	PsAttributeBnoIsolation, // PS_BNO_ISOLATION_PARAMETERS
	PsAttributeDesktopAppPolicy, // in ULONG
	PsAttributeChpe, // since REDSTONE3
} PS_ATTRIBUTE_ENUM;

#define PS_ATTRIBUTE_NUMBER_MASK  0x0000ffff
#define PS_ATTRIBUTE_THREAD       0x00010000 // can be used with threads
#define PS_ATTRIBUTE_INPUT        0x00020000 // input only
#define PS_ATTRIBUTE_UNKNOWN      0x00040000


#define PsAttributeValue(Number, Thread, Input, Unknown)\
	(((Number)  & PS_ATTRIBUTE_NUMBER_MASK) | \
	 ((Thread)  ? PS_ATTRIBUTE_THREAD : 0)  | \
	 ((Input)   ? PS_ATTRIBUTE_INPUT  : 0)  | \
	 ((Unknown) ? PS_ATTRIBUTE_UNKNOWN : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS \
	PsAttributeValue(PsAttributeParentProcess, false, true, true)
#define PS_ATTRIBUTE_DEBUG_PORT \
	PsAttributeValue(PsAttributeDebugPort, false, true, true)
#define PS_ATTRIBUTE_TOKEN \
	PsAttributeValue(PsAttributeToken, false, true, true)
#define PS_ATTRIBUTE_CLIENT_ID \
	PsAttributeValue(PsAttributeClientId, true, false, false)
#define PS_ATTRIBUTE_TEB_ADDRESS \
	PsAttributeValue(PsAttributeTebAddress, true, false, false)
#define PS_ATTRIBUTE_IMAGE_NAME \
	PsAttributeValue(PsAttributeImageName, false, true, false)
#define PS_ATTRIBUTE_IMAGE_INFO \
	PsAttributeValue(PsAttributeImageInfo, false, false, false)
#define PS_ATTRIBUTE_MEMORY_RESERVE \
	PsAttributeValue(PsAttributeMemoryReserve, false, true, false)
#define PS_ATTRIBUTE_PRIORITY_CLASS \
	PsAttributeValue(PsAttributePriorityClass, false, true, false)
#define PS_ATTRIBUTE_ERROR_MODE \
	PsAttributeValue(PsAttributeErrorMode, false, true, false)
#define PS_ATTRIBUTE_STD_HANDLE_INFO \
	PsAttributeValue(PsAttributeStdHandleInfo, false, true, false)
#define PS_ATTRIBUTE_HANDLE_LIST \
	PsAttributeValue(PsAttributeHandleList, false, true, false)
#define PS_ATTRIBUTE_GROUP_AFFINITY \
	PsAttributeValue(PsAttributeGroupAffinity, true, true, false)
#define PS_ATTRIBUTE_PREFERRED_NODE \
	PsAttributeValue(PsAttributePreferredNode, false, true, false)
#define PS_ATTRIBUTE_IDEAL_PROCESSOR \
	PsAttributeValue(PsAttributeIdealProcessor, true, true, false)
#define PS_ATTRIBUTE_UMS_THREAD \
	PsAttributeValue(PsAttributeUmsThread, true, true, false)
#define PS_ATTRIBUTE_MITIGATION_OPTIONS \
	PsAttributeValue(PsAttributeMitigationOptions, false, true, false)
#define PS_ATTRIBUTE_PROTECTION_LEVEL \
	PsAttributeValue(PsAttributeProtectionLevel, false, true, true)
#define PS_ATTRIBUTE_SECURE_PROCESS \
	PsAttributeValue(PsAttributeSecureProcess, false, true, false)
#define PS_ATTRIBUTE_JOB_LIST \
	PsAttributeValue(PsAttributeJobList, false, true, false)
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY \
	PsAttributeValue(PsAttributeChildProcessPolicy, false, true, false)
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY \
	PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, false, true, false)
#define PS_ATTRIBUTE_WIN32K_FILTER \
	PsAttributeValue(PsAttributeWin32kFilter, false, true, false)
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM \
	PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, false, true, false)
#define PS_ATTRIBUTE_BNO_ISOLATION \
	PsAttributeValue(PsAttributeBnoIsolation, false, true, false)
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY \
	PsAttributeValue(PsAttributeDesktopAppPolicy, false, true, false)

/*
#define PS_ATTRIBUTE_PARENT_PROCESS                   0x60000
#define PS_ATTRIBUTE_DEBUG_PORT                       0x60001
#define PS_ATTRIBUTE_TOKEN                            0x60002
#define PS_ATTRIBUTE_CLIENT_ID                        0x10003
#define PS_ATTRIBUTE_TEB_ADDRESS                      0x10004
#define PS_ATTRIBUTE_IMAGE_NAME                       0x20005
#define PS_ATTRIBUTE_IMAGE_INFO                       0x00006
#define PS_ATTRIBUTE_MEMORY_RESERVE                   0x20007
#define PS_ATTRIBUTE_PRIORITY_CLASS                   0x20008
#define PS_ATTRIBUTE_ERROR_MODE                       0x20009
#define PS_ATTRIBUTE_STD_HANDLE_INFO                  0x2000A
#define PS_ATTRIBUTE_HANDLE_LIST                      0x2000B
#define PS_ATTRIBUTE_GROUP_AFFINITY                   0x3000C
#define PS_ATTRIBUTE_PREFERRED_NODE                   0x2000D
#define PS_ATTRIBUTE_IDEAL_PROCESSOR                  0x3000E
#define PS_ATTRIBUTE_UMS_THREAD                       0x3000F
#define PS_ATTRIBUTE_MITIGATION_OPTIONS               0x20010
#define PS_ATTRIBUTE_PROTECTION_LEVEL                 0x60011
#define PS_ATTRIBUTE_SECURE_PROCESS                   0x20012
#define PS_ATTRIBUTE_JOB_LIST                         0x20013
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY             0x20014
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY  0x20015
#define PS_ATTRIBUTE_WIN32K_FILTER                    0x20016
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM    0x20017
#define PS_ATTRIBUTE_BNO_ISOLATION                    0x20018
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY               0x20019
*/

typedef struct _PS_ATTRIBUTE {
	unsigned long Attribute; // should be long long??
	size_t Size;
	union {
		unsigned long Value;
		void *ValuePtr;	
	};
	size_t *ReturnLength;
} PS_ATTRIBUTE;



typedef struct _PS_ATTRIBUTE_LIST {
	// Total size of the PS_ATTRIBUTE_LIST structure including all of its attribute
	// structures. 
	size_t TotalLength;

	// An array of process attributes. Must be a contiguous array at the
	// end of the attribute list
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;



typedef struct _PS_MEMORY_RESERVE {
	void *ReserveAddress;
	size_t ReserveSize;
} PS_MEMORY_RESERVE;

typedef enum _PS_STD_HANDLE_STATE {
	PsNeverDuplicate,
	PsRequestDuplicate,
	PsAlwaysDuplicate,
} PS_STD_HANDLE_STATE;


typedef struct _PS_STD_HANDLE_INFO {
	union {
		unsigned long Flags; // (PS_STD_* << 3) | PS_STD_HANDLE_STATE
/*
		struct {
			unsigned long StdHandleState : 2; // PS_STD_HANDLE_STATE	
			unsigned long PseudoHandleState : 3; // PS_STD_*
		};	
*/
	};
	unsigned long StdHandleSubsystemType;
} PS_STD_HANDLE_INFO;



/* Process Access Rights */

/**
 * Required to terminate a process using TerminateProcess.
*/
#define PROCESS_TERMINATE                 0x0001

/**
 * Required to create a thread.
*/
#define PROCESS_CREATE_THREAD             0x0002

/**
 * Required to perform an operation on the address space of a process.
 * VirtualProtectEx and WriteProcessMemory
*/
#define PROCESS_VM_OPERATION              0x0008

/**
 * Required to read memory in a process using ReadProcessMemory
*/
#define PROCESS_VM_READ                   0x0010

/**
 * Required to write memory in a process using WriteProcessMemory
*/
#define PROCESS_VM_WRITE                  0x0020

/**
 * Required to duplicate a handle using DuplicateHandle.
*/
#define PROCESS_DUP_HANDLE                0x0040

/**
 * Required to create a process
*/
#define PROCESS_CREATE_PROCESS            0x0080

/**
 * Required to set memory limits using SetProcessWorkingSetSize.
*/
#define PROCESS_SET_QUOTA                 0x0100

/**
 * Required to set certain information about a process, such as its
 * priority class using SetPriorityClass.
*/
#define PROCESS_SET_INFORMATION           0x0200

/**
 * Requried to retrive certain information about a process, such as its
 * token, exit code, and priority class (OpenProcessToken).
*/
#define PROCESS_QUERY_INFORMATION         0x0400

/**
 * Required to suspend or resume a process.
*/
#define PROCESS_SUSPEND_RESUME            0x0800

/**
 * Required to retrieve certain information about a process. A handle that
 * has the PROCESS_QUERY_INFORMATION access right is automatically granted
 * this right. Not supported on Windows Server 2003 and XP.
*/
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000




#define P_REQUEST_BREAKAWAY 0x01
#define PS_NO_DEBUG_INHERIT  0x02
#define PS_INHERIT_HANDLES   0x04
#define PS_UNKNOWN_VALUE     0x08

/* Process Create Flags */

#define PROCESS_CREATE_FLAGS_BREAKAWAY          0x0001
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT   0x0002
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES    0x0004
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE 0x0008
#define PROCESS_CREATE_FLAGS_LARGE_PAGES  0x0010

// Only usable with NtCreateUserProcess (Vista+)
#define PROCESS_CREATE_FLAGS_LARGE_PAGE_SYSTEM_DLL 0x0042
#define PROCESS_CREATE_FLAGS_PROTECTED_PROCESS     0x0040 // only allowed if the calling process is protected
#define PROCESS_CREATE_FLAGS_CREATE_SESSION 0x0080
#define PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT  0x0100
#define PROCESS_CREATE_FLAGS_SUSPENDED  0x0200
#define PROCESS_CREATE_FLAGS_EXTENDED_UNKNOWN 0x0400


unsigned long __stdcall NtCreateProcess(
	void **ProcessHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes, // OPTIONAL
	void *ParentProcess,
	bool InheritObjectTable,
	void *SectionHandle, // OPTIONAL
	void *DebugPort, // OPTIONAL
	void *ExceptionPort); // OPTIONAL


unsigned long __stdcall NtCreateProcessEx(
	void **ProcessHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes, // OPTIONAL
	void *ParentProcess,
	unsigned long Flags, 
	void *SectionHandle, // OPTIONAL
	void *DebugPort,     // OPTIONAL
	void *ExceptionPort, // OPTIONAL
	bool InJob);


unsigned long __stdcall NtCreateUserProcess(
	void **ProcessHandle,
	void **ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	OBJECT_ATTRIBUTES *ProcessObjectAttributes,
	OBJECT_ATTRIBUTES *ThreadObjectAttributes,
	unsigned long ProcessFlags,
	unsigned long ThreadFlags,
	RTL_USER_PROCESS_PARAMETERS *ProcessParameters,
	PS_CREATE_INFO *CreateInfo,
	PS_ATTRIBUTE_LIST *AttributeList);


unsigned long __stdcall NtTerminateProcess(
	void *ProcessHandle,
	unsigned long ExitStatus);


unsigned long __stdcall NtQueryInformationProcess
	(void *ProcessHandle,
	PROCESS_INFORMATION_CLASS ProcessInformationClass,
	void *ProcessInformation,
	unsigned long ProcessInformationLength,
	unsigned long *ReturnLength);


/*
unsigned long __stdcall NtQueryInformationProcess2
	(void *ProcessHandle,
	PROCESS_INFORMATION_CLASS ProcessInformationClass,
	void *ProcessInformation,
	unsigned long ProcessInformationLength,
	unsigned long *ReturnLength);
*/

unsigned long __stdcall NtOpenProcess
	(void **ProcessHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	CLIENT_ID *ClientId);






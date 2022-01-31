
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation, //obsolete
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotPatchInformation,
	SystemObjectSecurityMode,
	SystemWatchDogTimerHandle,
	SystemWatchDogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,

	SystemFullProcessInformation = 0x94,
	MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;


typedef struct _SYSTEM_BASIC_INFORMATION {
	unsigned long Reserved;
/**
 * The resolution of the hardware time. All time values in NT are specified as
 * 64-bit LARGE_INTEGER values in units of 100 nanoseconds. This field allows an
 * application to understand how many of the low order bits of a system time
 * value are insignificant. The values are limited to a maximum number of
 * 100-nanosecond units between clock ticks.
 * Also the number of 100-nanosecond units per clock tick for kernel intervals
 * measured in clock ticks.
*/
	unsigned long TimerResolution;

/**
 * The physical page size (in bytes) for virtual memory reservations is rounded.
 * The logical page size for virtual memory objects.
*/
	unsigned long PageSize;

/**
 * The number of physical pages managed by the operating system.
*/
	unsigned long NumberOfPhysicalPages;
	unsigned long LowestPhysicalPageNumber;
	unsigned long HighestPhysicalPageNumber;

/**
 * The granularity to which the base address of virtual memory reservations
 * is rounded. The logical page size for virtual memory objects.
 * Allocating 1 byte of virtual memory will actually allocate
 * AllocationGranularity bytes of virtual memory. Storing into that byte will
 * commit the first physical page of the virtual memory.
*/
	unsigned long AllocationGranularity;
	size_t MinimumUserModeAddress;
	size_t MaximumUserModeAddress;

/**
 * A bit mask representing the set of active processors in the system. Bit 0
 * is processor 0; bit 31 is processor 31.
*/
	size_t ActiveProcessorsAffinityMask;

/**
 * The number of logical processors in the current group.
*/
	char NumberOfProcessors;

} SYSTEM_BASIC_INFORMATION;






typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	unsigned long TickCount;
	void *StartAddress;
	CLIENT_ID ClientId;
	unsigned int CurrentPriority;
	unsigned int BasePriority;
// Total context switches
	unsigned int ContextSwitches;
	unsigned int ThreadState;
// The reason the thread is waiting
	unsigned int WaitReason;
	unsigned int Unknown;
} SYSTEM_THREAD_INFORMATION;



typedef struct _VM_COUNTERS
{
	unsigned long PeakVirtualSize;
	unsigned long VirtualSize;
	unsigned long PageFaultCount;
	unsigned long PeakWorkingSetSize;
	unsigned long WorkingSetSize;
	unsigned long QuotaPeakPagedPoolUsage;
	unsigned long QuotaPeakPoolUsage;
	unsigned long QuotaPeakNonPagedPoolUsage;
	unsigned long QuotaNonPagedPoolUsage;
	unsigned long PagefileUsage;
	unsigned long PeakPagefileUsage;
	unsigned long PrivatePageCount;
} VM_COUNTERS;


typedef struct _IO_COUNTERS
{
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} IO_COUNTERS;


typedef struct _SYSTEM_PROCESS_INFORMATION
{
	unsigned int NextEntryOffset;
	unsigned int NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	unsigned int HardFaultCount;
	unsigned int NumberOfThreadsHighWatermark;
	LARGE_INTEGER CycleTime;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	long BasePriority;
	void *UniqueProcessId;
	void *ParentProcessId;
	unsigned int HandleCount;
	unsigned int SessionId;
	unsigned long UniqueProcessKey;
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD_INFORMATION ThreadInfo[1];
} SYSTEM_PROCESS_INFORMATION;



unsigned long __stdcall NtQuerySystemInformation
	(SYSTEM_INFORMATION_CLASS SystemInformationClass,
	void *SystemInformation,
	unsigned long SystemInformationLength,
	unsigned long *ReturnLength);






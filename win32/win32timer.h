
typedef enum _TIMER_TYPE
{
// Manual-reset timer
	NotificationTimer,
	SynchronizationTimer
} TIMER_TYPE;

typedef enum _WAIT_TYPE
{
	WaitAll,
	WaitAny
} WAIT_TYPE;


#define TIMER_QUERY_STATE  0x01
#define TIMER_MODIFY_STATE 0x02


typedef enum _TIMER_INFORMATION_CLASS
{
	TimerBasicInformation
} TIMER_INFORMATION_CLASS;

typedef struct _TIMER_BASIC_INFORMATION
{
	LARGE_INTEGER RemainingTime;
	bool TimerState;
} TIMER_BASIC_INFORMATION;



typedef enum _TIMER_SET_INFORMATION_CLASS
{
	TimerSetCoalescableTimer
} TIMER_SET_INFORMATION_CLASS;


typedef void (__stdcall *PTIMER_APC_ROUTINE)(
	void *TimerContext,
	unsigned long TimerLowValue,
	long TimerHighValue);




typedef struct _COUNTED_REASON_CONTEXT
{
	unsigned long Version;
	unsigned long Flags;
	union {
		struct {
			UNICODE_STRING ResourceFileName;
			unsigned short ResourceReasonId;
			unsigned long StringCount;
			UNICODE_STRING *ReasonStrings;
		} DUMMYSTRUCTNAME;
		UNICODE_STRING SimpleString;
	} DUMMYUNIONNAME;
} COUNTED_REASON_CONTEXT;



typedef struct _TIMER_SET_COALESCABLE_TIMER_INFO
{
	LARGE_INTEGER DueTime;
	PTIMER_APC_ROUTINE TimerApcRoutine;
	void *TimerContext;
	COUNTED_REASON_CONTEXT *WakeContext;
	unsigned long Period;
	unsigned long TolerableDelay;
	bool *PreviousState;
} TIMER_SET_COALESCABLE_TIMER_INFO;


typedef struct _T2_SET_PARAMETERS_V0
{
	unsigned long Version;
	unsigned long Reserved;
	long long NoWakeTolerance;
} T2_SET_PARAMETERS;


unsigned long __stdcall NtCreateTimer
	(void **TimerHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	TIMER_TYPE TimerType);

unsigned long __stdcall NtCreateTimer2
	(void **TimerHandle,
	void *Reserved1,
	void *Reserved2,
	unsigned long Attributes,
	ACCESS_MASK DesiredAccess);


unsigned long __stdcall NtOpenTimer
	(void **TimerHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes);


unsigned long __stdcall NtSetTimer
	(void *TimerHandle,
	LARGE_INTEGER *DueTime,
	PTIMER_APC_ROUTINE TimerApcRoutine,
	void *TimerContext,
	bool ResumeTimer,
	long Period,
	bool *PreviousState);

unsigned long __stdcall NtSetTimer2
	(void *TimerHandle,
	LARGE_INTEGER *DueTime,
	LARGE_INTEGER *Period,
	T2_SET_PARAMETERS *Parameters);

unsigned long __stdcall NtSetTimerEx
	(void *TimerHandle,
	TIMER_SET_INFORMATION_CLASS TimerSetInfoClass,
	void *TimerSetInfo,
	unsigned long TimerSetInfoSize);


unsigned long __stdcall NtQueryTimer
	(void *TimerHandle,
	TIMER_INFORMATION_CLASS TimerInfoClass,
	void *TimerInfo,
	unsigned long TimerInfoSize,
	unsigned long *ReturnLength);

unsigned long __stdcall NtCancelTimer
	(void *TimerHandle,
	bool *CurrentState);


unsigned long __stdcall NtCancelTimer2
	(void *TimerHandle,
	void *Parameters);


unsigned long __stdcall NtSetTimerResolution
	(unsigned long DesiredResolution,
	bool SetResolution,
	unsigned long *CurrentResolution);


/**
 * MinResolution: Highest possible delay (in 100-ns units) between timer events.
 * MaxResolution: Highest possible delay (in 100-ns units) between timer events.
 * CurrentResolution: Current timer resolution, in 100-ns units.
*/
unsigned long __stdcall NtQueryTimerResolution
	(unsigned long *MinResolution,
	unsigned long *MaxResolution,
	unsigned long *CurrentResolution);




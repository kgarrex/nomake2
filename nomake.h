
#include "helper.h"

#define STATUS_SUCCESS                 0x00000000L
#define STATUS_WAIT_1                  0x00000001L
#define STATUS_USER_APC                0x000000C0L
#define STATUS_ALREADY_COMPLETE        0x000000FFL
#define STATUS_KERNEL_APC              0x00000100L
#define STATUS_ALERTED                 0x00000101L
#define STATUS_TIMEOUT                 0x00000102L
#define STATUS_PENDING                 0x00000103L


/*
 * Returned by enumeration APIs to indicate more information
 * is available to successive calls.
*/
#define STATUS_MORE_ENTRIES            0x00000105L


#define STATUS_NO_MORE_FILES           0x80000006L

/*
 * {No More Entries} No more entries are available from an
 * enumeration operation
*/
#define STATUS_NO_MORE_ENTRIES         0x8000001AL

#define STATUS_INFO_LENGTH_MISMATCH    0xC0000004L
#define STATUS_ACCESS_VIOLATION        0xC0000005L
#define STATUS_INVALID_HANDLE          0xC0000008L
#define STATUS_INVALID_CID             0xC000000BL
#define STATUS_INVALID_PARAMETER       0xC000000DL


/**
 * Conflicting Address Range. The specified address range
 * conflicts with the address space.
*/
#define STATUS_CONFLICTING_ADDRESSES   0xC0000018L

/*
 * {Access Denied} A process has requested access to an object
 * but has not been granted those access rights.
*/
#define STATUS_ACESS_DENIED            0xC0000022L


/*
 * {Buffer Too Small} The buffer is too small to contain the entry.
 * No information has been written to the buffer.
*/
#define STATUS_BUFFER_TOO_SMALL        0xC0000023L

/*
 * {Wrong Type} There is a mismatch between the type of object
 * that is required by the requested operation and the type of object
 * that is specified in the request.
*/
#define STATUS_OBJECT_TYPE_MISMATCH    0xC0000024L
#define STATUS_OBJECT_NAME_INVALID     0xC0000033L
#define STATUS_OBJECT_NAME_NOT_FOUND   0xC0000034L
#define STATUS_OBJECT_NAME_COLLISION   0xC0000035L
#define STATUS_OBJECT_PATH_INVALID     0xC0000039L
#define STATUS_OBJECT_PATH_SYNTAX_BAD  0xC000003BL
#define STATUS_INVALID_PAGE_PROTECTION 0xC0000045L


/**
 * An attempt was made to query image information on a section
 * that does not map an image.
 */
#define STATUS_SECTION_NOT_IMAGE       0xC0000049L

/**
 * A required privilege is not held by the client
 */
#define STATUS_PRIVILEGE_NOT_HELD      0xC0000061L

#define STATUS_MEMORY_NOT_ALLOCATED    0xC00000A0L

// The specified named pipe is in the closing state
#define STATUS_PIPE_CLOSING            0xC00000b1L
// The specified named pipe is in the connected state.
#define STATUS_PIPE_CONNECTED          0xC00000b2L
// The specified named pipe is in the listening state.
#define STATUS_PIPE_LISTENING          0xC00000b3L
#define STATUS_NOT_SUPPORTED           0xC00000BBL

// Used to indicate that a read operation was done on
// an empty pipe.
#define STATUS_PIPE_EMPTY              0xC00000D9L

#define STATUS_INVALID_PARAMETER_1     0xC00000EFL
#define STATUS_INVALID_PARAMETER_2     0xC00000F0L
#define STATUS_INVALID_PARAMETER_3     0xC00000F1L
#define STATUS_INVALID_PARAMETER_4     0xC00000F2L
#define STATUS_INVALID_PARAMETER_5     0xC00000F3L
#define STATUS_INVALID_PARAMETER_6     0xC00000F4L
#define STATUS_INVALID_PARAMETER_7     0xC00000F5L
#define STATUS_INVALID_PARAMETER_8     0xC00000F6L
#define STATUS_INVALID_PARAMETER_9     0xC00000F7L
#define STATUS_INVALID_PARAMETER_10    0xC00000F8L
#define STATUS_INVALID_PARAMETER_11    0xC00000F9L
#define STATUS_INVALID_PARAMETER_12    0xC00000FAL


/*
 * The object was not found
*/
#define STATUS_NOT_FOUND               0xC0000225L

#define STATUS_INVALID_PARAMETER_4     0xC00000F2L


#define STATUS_DLL_NOT_FOUND           0xC0000135L


#define ERROR_INVALID_MONITOR_HANDLE   0x000005B5L





#define FILE_DEVICE_8042_PORT           0x00000027
#define FILE_DEVICE_ACPI                0x00000032
#define FILE_DEVICE_BATTERY             0x00000029
#define FILE_DEVICE_BEEP                0x00000001
#define FILE_DEVICE_BUS_EXTENDER        0x0000002a
#define FILE_DEVICE_CD_ROM              0x00000002
#define FILE_DEVICE_CD_ROM_FILE_SYSTEM  0x00000003
#define FILE_DEVICE_CHANGER             0x00000030
#define FILE_DEVICE_CONTROLLER          0x00000004
#define FILE_DEVICE_DATALINK            0x00000005
#define FILE_DEVICE_DFS                 0x00000006
#define FILE_DEVICE_DFS_FILE_SYSTEM     0x00000035
#define FILE_DEVICE_DFS_VOLUME          0x00000036
#define FILE_DEVICE_DISK                0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM    0x00000008
#define FILE_DEVICE_DVD                 0x00000033
#define FILE_DEVICE_FILE_SYSTEM         0x00000009
#define FILE_DEVICE_FIPS                0x0000003a
#define FILE_DEVICE_FULLSCREEN_VIDEO    0x00000034
#define FILE_DEVICE_INPORT_PORT         0x0000000a
#define FILE_DEVICE_KEYBOARD            0x0000000b
#define FILE_DEVICE_KS                  0x0000002f
#define FILE_DEVICE_KSEC                0x00000039
#define FILE_DEVICE_MAILSLOT            0x0000000c
#define FILE_DEVICE_MASS_STORAGE        0x0000002d
#define FILE_DEVICE_MIDI_IN             0x0000000d
#define FILE_DEVICE_MIDI_OUT            0x0000000e
#define FILE_DEVICE_MODEM               0x0000002b
#define FILE_DEVICE_MOUSE               0x0000000f
#define FILE_DEVICE_MULTI_UNC_PROVIDER  0x00000010
#define FILE_DEVICE_NAMED_PIPE          0x00000011
#define FILE_DEVICE_NETWORK             0x00000012
#define FILE_DEVICE_NETWORK_BROWSER     0x00000013
#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014
#define FILE_DEVICE_NETWORK_REDIRECTOR  0x00000028
#define FILE_DEVICE_NULL                0x00000015
#define FILE_DEVICE_PARALLEL_PORT       0x00000016
#define FILE_DEVICE_PHYSICAL_NETCARD    0x00000017
#define FILE_DEVICE_PRINTER             0x00000018
#define FILE_DEVICE_SCANNER             0x00000019
#define FILE_DEVICE_SCREEN              0x0000001c
#define FILE_DEVICE_SERENUM             0x00000037
#define FILE_DEVICE_SERIAL_MOUSE_PORT   0x0000001a
#define FILE_DEVICE_SERIAL_PORT         0x0000001b
#define FILE_DEVICE_SMARTCARD           0x00000031
#define FILE_DEVICE_SMB                 0x0000002e
#define FILE_DEVICE_SOUND               0x0000001d
#define FILE_DEVICE_STREAMS             0x0000001e
#define FILE_DEVICE_TAPE                0x0000001f
#define FILE_DEVICE_TAPE_FILE_SYSTEM    0x00000020
#define FILE_DEVICE_TERMSRV             0x00000038
#define FILE_DEVICE_TRANSPORT           0x00000021
#define FILE_DEVICE_UNKNOWN             0x00000022
#define FILE_DEVICE_VDM                 0x0000002c
#define FILE_DEVICE_VIDEO               0x00000023
#define FILE_DEVICE_VIRTUAL_DISK        0x00000024
#define FILE_DEVICE_WAVE_IN             0x00000025
#define FILE_DEVICE_WAVE_OUT            0x00000026



#include "win32\win32mem.h"




typedef unsigned char * va_list;
#define va_start(list, param) (list = (((va_list)&param) + sizeof(param)))
#define va_arg(list, type) (*(type*)((list += sizeof(type)) - sizeof(type)))
#define va_end(list) (list = 0)


#if defined (INCLUDE_KERNEL32)

unsigned int __stdcall FormatMessageW
	(unsigned int dwFlags,
	 void * const lpSource,
	 unsigned int dwMessageId,
	 unsigned int dwLanguageId,
	 wchar_t lpBuffer[],
	 unsigned int nSize,
	 va_list *Arguments);


unsigned int __stdcall FormatMessageA
	(unsigned int dwFlags,
	 void * const lpSource,
	 unsigned int dwMessageId,
	 unsigned int dwLanguageId,
	 char lpBuffer[],
	 unsigned int nSize,
	 va_list *Arguments);




int __stdcall WriteConsoleW
	(void *ConsoleOutputHandle,
	 const wchar_t *Buffer,
	 unsigned int NumOfCharsToWrite,
	 unsigned int *NumCharsWritten,
	 void * Reserved);


int __stdcall WriteConsoleA
	(void *ConsoleOutputHandle,
	 const char *Buffer,
	 unsigned int NumOfCharsToWrite,
	 unsigned int *NumCharsWritten,
	 void * Reserved);



void * __stdcall GetStdHandle(unsigned int StdHandle);


DWORD __stdcall WaitForSingleObject(void *Handle, DWORD Milliseconds);


void __cdecl LogMessageW(wchar_t *msg, ...)
{

	unsigned int numToWrite;
	unsigned int numWritten;
	va_list args;

	wchar_t buffer[256];
	// Write message to standard output
	//numToWrite = swprintf_s(buffer, 256, msg);
	va_start(args, msg);
	numToWrite = FormatMessageW(0x400, msg, 0, 0, buffer, 256, &args);
	if(numToWrite == 0){
		return;	
	}
	if(!WriteConsoleW(GetStdHandle(
		(unsigned int)-11), buffer, numToWrite, &numWritten, 0))
	{
		return;	
	}

	va_end(args);

}



void __cdecl LogMessageA(char *msg, ...)
{

	unsigned int numToWrite;
	unsigned int numWritten;
	va_list args;

	char buffer[256];
	// Write message to standard output
	//numToWrite = swprintf_s(buffer, 256, msg);
	va_start(args, msg);
	numToWrite = FormatMessageA(0x400, msg, 0, 0, buffer, 256, &args);
	if(numToWrite == 0){
		return;	
	}
	if(!WriteConsoleA(GetStdHandle(
		(unsigned int)-11), buffer, numToWrite, &numWritten, 0))
	{
		return;	
	}

	va_end(args);

}



#endif



unsigned long NTSTATUS;

typedef union _LARGE_INTEGER {
	struct {
		unsigned long LowPart;
		long HighPart;	
	};
	struct {
		unsigned long LowPart;
		long HighPart;	
	} u;
	long long QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;


typedef struct _SECURITY_ATTRIBUTES {
	DWORD SizeOf;
	void *SecurityDescriptor;
	bool InheritHandle;
} SECURITY_ATTRIBUTES;



typedef struct _UNICODE_STRING {
/**
 * Specifies the length, in bytes, of the string pointed to by the buffer member,
 * not including the terminating NULL character, if any.
*/
	unsigned short Length;

/**
 * Specifies the total size, in bytes, or memory allocated for buffer, Up to
 * maximum_length bytes may be written into the buffer without trampling memory.
*/
	unsigned short MaximumLength;

/**
 * Pointer to a wide-character string.
*/
	wchar_t *Buffer;
} UNICODE_STRING;



typedef struct _ANSI_STRING {
	unsigned short Length;
	unsigned short MaximumLength;
	char *Buffer;
} ANSI_STRING;



typedef union _ACCESS_MASK {
	unsigned long mask;
	struct {
		short SpecificRights;
		char StandardRights;
		char AccessSystemAcl:1;
		char Reserved:3;
		char GenericAll:1;
		char GenericExecute:1;
		char GenericWrite:1;
		char GenericRead:1;
	};
} ACCESS_MASK;


/**
 * Required to delete the object.
*/
#define DELETE                     (0x00010000L)

/**
 * Required to read information in the security descriptor for the object,
 * not including the information in the SACL. To read or write the SACL, you
 * must request the ACCESS_SYSTEM_SECURITY access right. 
*/
#define READ_CONTROL               (0x00020000L)

/**
 * Required to modify the DACL in the security descriptor for the object.
*/
#define WRITE_DAC                  (0x00040000L)

/**
 * Required to change the owner in the security descriptor for the object
*/
#define WRITE_OWNER                (0x00080000L)

/*
 * The right to used the object for synchronization. This enables
 * a thread to wait until the object is in the signaled state. Some
 * object types do not support this access right.
 * For asynchronous file I/O operations, you should wait on the event handle in an
 * OVERLAPPED structure rather than using the file handle for synchronization.
 */
#define SYNCHRONIZE                (0x00100000L)


/**
 * Combines DELETE, READ_CONTROL, WRITE_DAC, and WRITE_ONWER access.
*/
#define STANDARD_RIGHTS_REQUIRED   (0x000F0000L)


/**
 * Includes READ_CONTROL, which is the right to read the information in the file
 * or directory object's security descriptor. This does not include the info
 * in the SACL.
*/
#define STANDARD_RIGHTS_READ       (READ_CONTROL)
#define STANDARD_RIGHTS_WRITE      (READ_CONTROL)
#define STANDARD_RIGHTS_EXECUTE    (READ_CONTROL)

/**
 * Combines DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, and 
 * SYNCHRONIZE access.
*/
#define STANDARD_RIGHTS_ALL        (0x001F0000L)
#define SPECIFIC_RIGHTS_ALL        (0x0000FFFFL)




// Define access rights to files and directories
/*
 * Query access to the directory object.
*/
#define DIRECTORY_QUERY                0x00000001

/*
 * Name-lookup access to the directory object.
*/
#define DIRECTORY_TRAVERSE             0x00000002

/*
 * Name-creation access to the directory object.
*/
#define DIRECTORY_CREATE_OBJECT        0x00000004

/*
 * Subdirectory-creation access to the directory object.
*/
#define DIRECTORY_CREATE_SUBDIRECTORY  0x00000008

#define DIRECTORY_ALL_ACCESS  (STANDARD_RIGHTS_REQUIRED | 0xf)






typedef struct _IO_STATUS_BLOCK {
	union {
		unsigned long Status;
		void *Pointer;
	} DUMMYUNIONNAME;
	void *Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;





// Define the create/open option flags

/**
 * This handle can be inherited by child processes of the current process.
 */
#define OBJ_INHERIT                        0x00000002L

/**
 * This flag only applies to objects that are named within the object
 * manager. By default, such objects are deleted when all open handles to
 * them are closed. If this flag is specified, the object is not deleted
 * when all open handles are closed. Drivers can use ZwMakeTemporaryObject
 * to delete permanent objects.
 */
#define OBJ_PERMANENT                      0x00000010L

/**
 * If this flag is set and the OBJECT_ATTRIBUTES structure is passed to a
 * routine that creates an object, the object can be accessed exclusively.
 * That is, once a process opens such a handle to the object, no other
 * processes can open handles to this object.
 * If this flag is set and the OBJECT_ATTRIBUTES structure is pasesed to a
 * routine that creates an object handle, the caller is requesting exclusive
 * access to the object for the process context that the handle was created in.
 * This request can be granted only if the OBJ_EXCLUSIVE flag was set when the
 * object was created.
 */
#define OBJ_EXCLUSIVE                      0x00000020L

/**
 * If this flag is specified, a case-insensitive comparison is used when
 * matching the ObjectName parameter against the names of existing objects.
 * Otherwise, object names are compared using the default system settings.
 */
#define OBJ_CASE_INSENSITIVE               0x00000040L

/**
 * If this flag is specified to a routine that creates object, and that
 * object already exists then the routine should open that object. Otherwise,
 * the routine creating the object returns an NTSTATUS code of
 * STATUS_OBJECT_NAME_COLLISION.
 */
#define OBJ_OPENIF                         0x00000080L

/**
 * If an object handle, with this flag set, is passed to a routine that
 * opens objects and if the object is a symbolic link object, the routine
 * should open the symbolic link object itself, rather than the object that
 * the symbolic link refers to (which is the default behavior).
*/
#define OBJ_OPENLINK                       0x00000100L

/**
 * Specifies that the handle can only be accessed in kernel mode.
 */
#define OBJ_KERNEL_HANDLE                  0x00000200L

/**
 * The routine opening the handle should enforce all access checks for
 * the object, even if the handle is being opened in kernel mode.
 */
#define OBJ_FORCE_ACCESS_CHECK             0x00000400L

#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP  0x00000800L


typedef struct _OBJECT_ATTRIBUTES {
/**
 * The number of bytes of data contained in this structure. This should be
 * set to sizeof(OBJECT_ATTRIBUTES)
*/
	unsigned long SizeOf;

/**
 * Optional handle to the root object directory for the path name specified
 * by the ObjectName member. If RootDirectory is NULL, ObjectName must point
 * to a fully qualified object name that includes the full path to the 
 * target object. If RootDirectory is non-NULL, ObjectName specifies an
 * object name relative to the RootDirectory directory. The RootDirectory
 * handle can refer to a file system directory or an object directory in the
 * object manager namespace.
*/
	void *RootDirectory;

/**
 * Pointer to a UNICODE_STRING that contains the name of the object for which
 * a handle is to be opened. This must either be a fully qualified object
 * name, or a relative path name to the directory specified by the
 * RootDirectory member.
*/
	UNICODE_STRING *ObjectName;

/**
 * Bitmask of flags that specify object handle attributes
*/
	unsigned long Attributes;

/**
 * Specifies a security descriptor (SECURITY_DESCRIPTOR) for the object when
 * the object is created. If this member is NULL, the object will receive
 * default security settings.
*/
	void *SecurityDescriptor;

/**
 * Optional quality of service to be applied to the object when it is created.
 * Used to indicate the security impersonation level and context tracking
 * mode (dynamic or static). This value is typically NULL.
*/
	void *SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


typedef struct _GUID
{
	unsigned long Data1;
	unsigned short Data2;
	unsigned short Data3;
	unsigned char Data4[8];
} GUID;




size_t mbstowcs(wchar_t *dest, char *src, size_t n);


/**
 * Copies the contents of a source memory block to a destination memory block.
*/
void * __stdcall memcpy(
	void *Destination,
	const void *Source,
	size_t Length);



void __stdcall RtlInitUnicodeString(
	UNICODE_STRING *OutString,
	const wchar_t *InString);


void __stdcall RtlZeroMemory(
	void *Destination,
	size_t Length);


typedef void (__stdcall *PIO_APC_ROUTINE)(void *, struct _IO_STATUS_BLOCK *, unsigned long); 


typedef struct _CSR_API_MSG {
	long NOT_COMPLETE;
/*
	PORT_MESSAGE h;
	union {

	};
*/
} CSR_API_MSG;


typedef struct _CLIENT_ID {
	void *ProcessHandle;
	void *ThreadHandle;
} CLIENT_ID;



#include "win32\win32sys.h"



typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
	IoCompletionBasicInformation,
} IO_COMPLETION_INFORMATION_CLASS;


typedef struct _IO_COMPLETION_BASIC_INFORMATION
{
	// Number of currently pending file operations for specified
	// IO Completion Object.
	unsigned long Depth;
} IO_COMPLETION_BASIC_INFORMATION;


typedef struct _FILE_IO_COMPLETION_INFORMATION
{
	void *KeyContext;
	void *ApcConext;
	IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION;


typedef struct _FILE_IO_COMPLETION_NOTIFICATION_INFORMATION
{
	unsigned long Flags;
} FILE_IO_COMPLETION_NOTIFICATION_INFORMATION;


typedef struct _FILE_ACCESS_INFORMATION
{
	ACCESS_MASK Access;
} FILE_ACCESS_INFORMATION;


/*
typedef struct _DRIVER_OBJECT {
	short Type;
	short Size;
	struct _DEVICE_OBJECT *DeviceObject;
	unsigned long Flags;
	void *DriverSection;
	struct _DRIVER_EXTENSION *DriverExtension;
	struct _UNICODE_STRING DriverName;
	struct _UNICODE_STRING *HardwareDatabase;
	PFAST_IO_DISPATCH FastIoDispatch;
	PDRIVER_INITIALIZE_ROUTINE DriverInit;
	PDRIVER_STARTIO_ROUTINE DriverStartIo;
	PDRIVER_UNLOAD_ROUTINE DriverUnload;
	PDRIVER_DISPATCH_ROUTINE MajorFunction[IRP_MJ_MAXIMUM_FUNCTION];
} DRIVER_OBJECT, *PDRIVER_OBJECT;
*/

typedef struct _FILE_OBJECT {
	short Type;
	/*
	short Size;
	struct _DEVICE_OBJECT *DeviceObject;
	struct _VPB *Vpb;
	void *FsContext;
	void *FsContext2;
	struct _SECTION_OBJECT_POINTERS *SectionObjectPointer;
	void *PrivateCacheMap;
	long FinalStatus;
	struct _FILE_OBJECT *RelatedFileObject;
	unsigned char LockOperation;
	unsigned char DeletePending;
	unsigned char ReadAccess;
	unsigned char WriteAccess;
	unsigned char DeleteAccess;
	unsigned char SharedRead;
	unsigned char SharedWrite;
	unsigned char SharedDelete;
	unsigned long Flags;
	UNICODE_STRING FileName;
	LARGE_INTEGER CurrentByteOffset;
	unsigned long Waiters;
	unsigned long Busy;
	void *LastLock;
	struct _KEVENT Lock;
	struct _KEVENT Event;
	struct _IO_COMPLETION_CONTEXT *CompletionContext;
	ULONG IrpListLock;
	struct _LIST_ENTRY IrpList;
	void *FileObjectExtension;
	*/
} FILE_OBJECT, *PFILE_OBJECT;



#include "win32\win32io.h"

#include "win32\win32section.h"

typedef struct _LIST_ENTRY {
	struct _LIST_ENTRY *Flink;
	struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, PRLIST_ENTRY;


typedef struct _LDR_DATA_TABLE_ENTRY
{
	void * Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	void *Reserved2[2];
	void *DllBase;
	void *Reserved3[2];
	UNICODE_STRING FullDllName;
	char Reserved4[8];
	void *Reserved5[3];
	union {
		unsigned long CheckSum;
		void *Reserved6;
	};
	unsigned long TimeDateStamp;
} LDR_DATA_TABLE_ENTRY;


typedef struct _RTL_CRITICAL_SECTION_DEBUG {
	unsigned short Type;
	unsigned short CreatorBackTraceIndex;
	struct _RTL_CRITICAL_SECTION *CriticalSection;
	LIST_ENTRY ProcessLocksList;
	unsigned long EntryCount;
	unsigned long ContentionCount;
	unsigned long Flags;
	unsigned short CreatorCBackTraceIndexHigh;
	unsigned short SpareWord;
} RTL_CRITICAL_SECTION_DEBUG, RTL_RESOURCE_DEBUG;


typedef struct _RTL_CRITICAL_SECTION {
	RTL_CRITICAL_SECTION_DEBUG *DebugInfo;

	unsigned long LockCount;
	unsigned long RecursionCount;
	void *OwningThreadHandle;
	void *LockSemaphoreHandle;
	unsigned long SpinCount;
} RTL_CRITICAL_SECTION;






// get multiple for 32 or 64 bit
#define MULTIPLE() (sizeof(void*) / 4)


typedef struct _GDI_TEB_BATCH
{
	unsigned long Offset;
	void *HDC;
	unsigned long Buffer[0x136];
} GDI_TEB_BATCH;


typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
	struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME *Previous;
	struct _ACTIVATION_CONTEXT *ActivationContext;
	unsigned long Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME;


typedef struct _ACTIVATION_CONTEXT_STACK
{
	unsigned long Flags;
	unsigned long NextCookieSequenceNumber;
	RTL_ACTIVATION_CONTEXT_STACK_FRAME *ActiveFrame;
	LIST_ENTRY FrameListCache;
} ACTIVATION_CONTEXT_STACK;


#include "win32\win32timer.h"


// Define 128-bit 16-byte aligned xmm register type
typedef struct _M128A {
	unsigned long long Low;
	long long High;
} M128A, *PM128A;



#include "win32\win32process.h"
#include "win32\win32thread.h"


#include "win32\win32reg.h"


/**
 * ObjectHandle: HANDLE to alertable object.
 * Alertable: If set, calling thread is signaled, so all queued APC routines
 * are executed.
 * Timeout: Time-out interval, in microseconds. NULL means infinite.
*/
unsigned long __stdcall NtWaitForSingleObject
	(void *ObjectHandle,
	bool Alertable,
	LARGE_INTEGER *Timeout);


typedef enum _OBJECT_WAIT_TYPE
{
	WaitAllObject,
	WaitAnyObject
} OBJECT_WAIT_TYPE;

unsigned long __stdcall NtWaitForMultipleObjects
	(unsigned long ObjectCount,
	void **ObjectsArray,
	OBJECT_WAIT_TYPE WaitType,
	bool Alertable,
	LARGE_INTEGER *Timeout);


typedef enum _EVENT_TYPE
{
	NotificationEvent,
	SynchronizationEvent
} EVENT_TYPE;





/**
 * Calls an API routine in a CSRSS server DLL and waits for the reply.
*/

unsigned long __stdcall CsrClientCallServer(
	CSR_API_MSG *ApiMsg,
	void *CaptureBuffer,
	unsigned long ApiNumber,
	long ApiMessageDataSize);



#define DUPLICATE_CLOSE_SOURCE    0x1
#define DUPLICATE_SAME_ACCESS     0x2
#define DUPLICATE_SAME_ATTRIBUTES 0x4

/**
 * Creates a handle that is a duplicate of the specified source handle.
*/
unsigned long __stdcall NtDuplicateObject(
	void *SourceProcessHandle,
	void *SourceHandle,
	void *TargetProcessHandle,
	void **TargetHandle,
	ACCESS_MASK DesiredAccess,
	unsigned long HandleAttributes,
	unsigned long Options);



#include "win32\win32file.h"

unsigned long __stdcall NtClose(void *Handle);


unsigned long __stdcall NtOpenDirectoryObject(
	void **DirectoryHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *pObjectAttr);




unsigned long __stdcall NtCreateEvent(
	void **EventHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	unsigned long EventType,
	bool InitialState);



unsigned long __stdcall NtClose(void *Handle);

unsigned long __stdcall NtCreateDirectoryObject(
	void **pDirectoryHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes);

unsigned long __stdcall NtCreateDirectoryObjectEx(
	void **pDirectoryHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	void *ShadowDirectoryHandle,
	unsigned long Flags);



unsigned long __stdcall LdrGetProcedureAddress(
	void *ModuleHandle,
	ANSI_STRING *FunctionName,
	unsigned short Ordinal,
	void **FunctionAddress);

unsigned long __stdcall LdrLoadDll(
	wchar_t *PathToFile,
	unsigned long Flags,
	UNICODE_STRING *ModuleFileName,
	void **ModuleHandle);

unsigned long __stdcall LdrGetDllHandle(
	wchar_t *Path,
	void *Unused,
	UNICODE_STRING *ModuleFileName,
	void **ModuleHandle);

unsigned long __stdcall LdrUnloadDll(
	void *Handle);


unsigned long __stdcall NtQueryPerformanceCounter
	(LARGE_INTEGER *PerformanceCounter,
	LARGE_INTEGER *PerformanceFrequency);




unsigned long __stdcall ZwDeviceIoControlFile(
	void *FileHandle,
	void *Event,
	PIO_APC_ROUTINE ApcRoutine,
	void *ApcContext,
	IO_STATUS_BLOCK *IoStatusBlock,
	unsigned long IoControlCode,
	void *InputBuffer,
	unsigned long InputBufferLength,
	void *OutputBuffer,
	unsigned long OutputBufferLength);






// kernel32.dll
unsigned int __stdcall GetLastError();
void *__stdcall LoadLibraryW(wchar_t *FileName);



#define NotificationEvent     0
#define SynchronizationEvent  1


typedef struct nm_app {
	unsigned long mem;	
} nm_app_t;


typedef struct nm_process {
	nm_app_t *app;
} nm_process_t;

typedef struct nm_lib {
	nm_app_t *app;
	void *handle;
} nm_lib_t;



typedef struct nm_str {
	char *buffer;         // byte pointer to code points
	unsigned int length;  // total length in bytes
	unsigned int max;     // max number of bytes in buffer
	int encoding; // encoding
} nm_str_t;





typedef struct nm_dir {
	nm_app_t *app;

	unsigned int refCount;
	void *handle;
	nm_str_t *name;
} nm_dir_t;




typedef struct nm_file {
	void *handle;
	void *event;
	unsigned int filetype;

	char *name;

	nm_dir_t *dir;
	
// has the file been written to and exists on disk
	bool isWritten;
} nm_file_t;



/**
 * The difference between two points in time. Used by stopwatch
 * and datetime comparisons.
*/
typedef struct nm_timediff {
	unsigned long long time;
} nm_timediff_t;


/**
 * The difference in two points in time
*/
typedef struct nm_time {
	unsigned long time;
} nm_time_t;


typedef struct nm_timer {
	nm_app_t *app;
	unsigned long time;
} nm_timer_t;


typedef struct nm_stopwatch {
	nm_app_t *app;
	unsigned long long watch;

#if defined(NOMAKE_WINDOWS)
	LARGE_INTEGER counter;
	LARGE_INTEGER frequency;
#endif
} nm_stopwatch_t;


nm_stopwatch_t * __stdcall nm_stopwatch_new(nm_app_t *app);

void  __stdcall nm_stopwatch_start(nm_stopwatch_t *watch);

nm_timediff_t *__stdcall nm_stopwatch_stop(nm_stopwatch_t *watch);

void __stdcall nm_stopwatch_reset(nm_stopwatch_t *watch);

nm_time_t *__stdcall nm_stopwatch_get_time(nm_stopwatch_t *watch);




void * __stdcall nm_malloc(size_t size);

void __stdcall nm_free(void *ptr);


/**
 * Copies memory from source to the destination
 * Returns the destination
*/
void * __stdcall nm_memcpy(void *dest, void *src, size_t len);



/**
 * Allocate a new utf8 string buffer
 * If str is NULL and size is greater than zero, a buffer is allocated
 * to store a string
*/
nm_str_t * __stdcall nm_str_new(char *str, size_t size);


/**
 * Delete a string
*/
void __stdcall nm_str_delete(nm_str_t *str);



nm_lib_t * __stdcall nm_lib_load(wchar_t *filepath);



/**
 * Returns the number of bytes currenty stored in the buffer
*/
uint32_t nm_str_add_code_point(nm_str_t *str, uint32_t cp);




typedef int (__cdecl *nm_dir_traverse_callback)(nm_file_t *file, void *);



nm_dir_t * __stdcall nm_dir_open(nm_app_t *app, char *path, size_t length);

/**
 * Check if a directory exists in the filesystem
*/
bool __stdcall nm_dir_exists(char *path, size_t length);

/**
 * Close a directory
*/
void __stdcall nm_dir_close(nm_dir_t *dir);


/**
 * Closes a directory and deletes it from the filesystem.
 * This deletes all files and subdirectories
*/
void __stdcall nm_dir_delete(nm_dir_t *dir);



/**
 * Traverse the files in a directory and call a callback for each file
*/
void __stdcall nm_dir_traverse(
	nm_dir_t *dir,
	nm_dir_traverse_callback callback,
	void *argument);



nm_file_t * __stdcall nm_file_open(
	nm_app_t *app,
	nm_dir_t *dir,
	char *name, uint32_t length);


unsigned int nm_dir_file_count(nm_dir_t *dir);

//nm_dir_traverse();


int __cdecl nm_printf(char *format, ...);

void nm_sprintf();

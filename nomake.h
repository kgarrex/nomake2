
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
#define STATUS_INVALID_CID             0xC000000BL
#define STATUS_INVALID_PARAMETER       0xC000000DL
#define STATUS_INVALID_HANDLE          0xC0000008L


/**
 * Conflicting Address Range. The specified address range
 * conflicts with the address space.
*/
#define STATUS_CONFLICTING_ADDRESSES   0xC0000018L

/*
 * {Buffer Too Small} The buffer is too small to contain the entry.
 * No information has been written to the buffer.
*/
#define STATUS_BUFFER_TOO_SMALL        0xC0000023L

/*
 * {Access Denied} A process has requested access to an object
 * but has not been granted those access rights.
*/
#define STATUS_ACESS_DENIED            0xC0000022L

/*
 * {Wrong Type} There is a mismatch between the type of object
 * that is required by the requested operation and the type of object
 * that is specified in the request.
*/
#define STATUS_OBJECT_TYPE_MISMATCH    0xC0000024L
#define STATUS_OBJECT_NAME_NOT_FOUND   0xC0000034L
#define STATUS_OBJECT_NAME_COLLISION   0xC0000035L
#define STATUS_OBJECT_PATH_INVALID     0xC0000039L
#define STATUS_OBJECT_PATH_SYNTAX_BAD  0xC000003BL
#define STATUS_INVALID_PAGE_PROTECTION 0xC0000045L

#define STATUS_MEMORY_NOT_ALLOCATED    0xC00000A0L

/*
 * The object was not found
*/
#define STATUS_NOT_FOUND               0xC0000225L

#define STATUS_INVALID_PARAMETER_4     0xC00000F2L


#define ERROR_INVALID_MONITOR_HANDLE   0x000005B5L






/*  Virtual Allocation Type Flags */

/**
 * The specified region of pages is to be committed.
*/
#define MEM_COMMIT   0x00001000

/**
 * The specified region of pages is to be reserved.
*/
#define MEM_RESERVE  0x00002000

/**
 * Reset the state of the specified region so that if the pages are in
 * paging file, they are discarded and pages of zeros are brought in. If the
 * pages are in memory and modified, they are marked as not modified so that
 * they will not be written out to the paging file. The contents are not
 * zeroed. The Protect parameter is not used, but it must be set to a valid value.
 * If MEM_RESET is set, no other flag may be set.
*/
#define MEM_RESET    0x00080000

/**
 * 
*/
#define MEM_RESET_UNDO  0x10000000
#define MEM_LARGE_PAGES 0x20000000
#define MEM_PHYSICAL    0x00400000

/**
 * Allocates memory at the highest possible address. This can be slower than
 * regular allocations, especially when there are many allocations.
*/
#define MEM_TOP_DOWN    0x00100000
#define MEM_WRITE_WATCH 0x00200000






/* Virtual Free Type Flags */
/**
 * Decommits the specified region of committed pages. After the operation, the
 * pages are in the reserved state.
 * The function does not fail if you attempt to decommit an uncommitted page.
 * This means that you can decommit a range of pages without first determining
 * the current commitment state.
 * The MEM_DECOMMIT value is not supported when the lpAddress parameter provides
 * the base address for an enclave.
*/
#define MEM_DECOMMIT  0x00004000


/**
 * Releases the specified region of pages, or placeholder (for a placeholder,
 * the address space is released and available for other allocations.) After
 * this operation, the pages are in the free state.
 * If you specify this value, dwSize must be 0 (zero), and lpAddress must point
 * to the base address returned by the VirtualAlloc funtion when the region is
 * reserved. The function fails if either of these conditions is not met.
 * If any pages in the region are committed currently, the function first
 * decommits, and then releases them.
 * The function does not fail if you attempt to release pages that are in
 * different states, some reserved and some committed. This means that you can
 * release a range of pages without first determining the current commitment
 * state.
*/
#define MEM_RELEASE   0x00008000






/* Virtual Allocation Protection Flags */

/**
 * No access to the committed region of pages is allowed. An attempt to read,
 * write, or execute the committed region results in an access violation
 * exception, called a general protection (GP) fault.
*/
#define PAGE_NOACCESS           0x00000001

/**
 * Read-only and execute access to the committed region of pages is allowed. An
 * attempt to write the committed region results in an access violation.
*/
#define PAGE_READONLY           0x00000002

/**
 * Read, write, and execute access to the committed region of pages is allowed. If
 * write access to the underlying section is allowed, then a single copy of the
 * pages is shared. Otherwise the pages are shared read only/copy on write.
*/
#define PAGE_READWRITE           0x00000004

/**
 * Enables read-only or copy-on-write access to a mapped view of a file
 * mapping object. An attempt to wite to a committed copy-on-wite page results
 * in a private copy of the page being made for the process. The private page
 * is marked as PAGE_READWRITE, and the change is written to the new page. If
 * Data Execution Prevention is enabled, attempting to execute code in the 
 * committed region results in an access violation.
*/
#define PAGE_WRITECOPY           0x00000008

/**
 * Execute access to the committed region of pages is allowed. An attempt to read
 * or write to the committed region results in an access violation.
*/
#define PAGE_EXECUTE             0x00000010

/**
 * Execute and read access to the committed region of pages are allowed. An
 * attempt to write to the committed region results in an access violation.
*/
#define PAGE_EXECUTE_READ        0x00000020

/**
 * Enables execute, read-only, or read/write access to the committed region of
 * pages.
*/
#define PAGE_EXECUTE_READWRITE   0x00000040

/**
 * Enables execute, read-only, or copy-on-write access to a mapped view of a file
 * mapping object. An attempt to write to a committed copy-on-write page results
 * in a private copy of the page being made for the process. The private page
 * is marked as PAGE_EXECUTE_READWRITE, and the change is written to the new page.
*/
#define PAGE_EXECUTE_WRITECOPY    0x00000080

/**
 * Pages in the region become guard pages. Any attempt to read from or write to
 * a guard page causes the system to raise a STATUS_GUARD_PAGE exception. Guard
 * pages thus act as a one-shot access alarm. This flag is a page protection
 * modifier, valid only when used with one of the page protetion flags other than
 * PAGE_NOACCESS. When an access attempt leads the system to turn off guard page
 * status, the underlying page protection takes over. If a guard page exception
 * occurs during a system service, the service typically returns a failure
 * status indicator.
*/
#define PAGE_GUARD               0x00000100

/**
 * The region of pages should be allocated as noncacheable. PAGE_NOCACHE is not
 * allowed for sections.
*/
#define PAGE_NOCACHE             0x00000200

/**
 * Enables write combining, that is, coalescing writes from cache to main memory,
 * where the hardware supports it. This flag is used primarily for frame buffer
 * memory so that writes to the same cache line are combined where possible
 * before being written to the device. This can greatly reduce writes across the
 * bus to (for example) video memory. If the hardware does not support write
 * combining, the flag is ignored. This flag is a page protection modifier,
 * valid only when used with one of the page protection flags other than
 * PAGE_NOACCESS.
*/
#define PAGE_WRITECOMBINE    0x00000400



// TODO (Garrett) Type out the descriptions of each flag
/* Section Allocation Attributes */


/**
 * Map section at same address in each process
*/
#define SEC_BASED            0x00200000

/**
 * Disables changes to protection of pages
*/
#define SEC_NO_CHANGE        0x00400000

/**
 * Map section as an image
*/
#define SEC_IMAGE            0x01000000

/**
 * Map section in VLM region
*/
#define SEC_VLM              0x02000000

/**
 * Reserve without allocating pagefile storage
*/
#define SEC_RESERVE          0x04000000

/**
 * Commit pages; the default behavior
*/
#define SEC_COMMIT           0x08000000

/**
 * Mark pages as non-cacheable
*/
#define SEC_NOCACHE          0x10000000
#define SEC_WRITECOMBINE     0x40000000
#define SEC_IMAGE_NO_EXECUTE 0x11000000
#define SEC_LARGE_PAGES      0x80000000







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



typedef struct _UNICODE_STRING {
/**
 * Specifies the length, in bytes, of the string pointed to by the buffer member,
 * not including the terminating NULL character, if any.
*/
	unsigned short length;

/**
 * Specifies the total size, in bytes, or memory allocated for buffer, Up to
 * maximum_length bytes may be written into the buffer without trampling memory.
*/
	unsigned short maximum_length;

/**
 * Pointer to a wide-character string.
*/
	wchar_t *buffer;
} UNICODE_STRING;



typedef struct _ANSI_STRING {
	unsigned short length;
	unsigned short maximum_length;
	char *buffer;
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


// File specfic access rights
/*
 * Read data from the file
*/
#define FILE_READ_DATA                0x00000001


/*
 * Write Data to the file
*/
#define FILE_WRITE_DATA               0x00000002

/*
 * Read the extended attributes (EA) of the file. This flag is
 * irrelevant for device and intermediate drivers.
*/
#define FILE_READ_EA                  0x00000008

/*
 * Change the extended attributes (EA) of the file. This flag is
 * irrelevant for device and intermediate drivers.
*/
#define FILE_WRITE_EA                 0x00000010

/*
 * Read the attributes of the file.
*/
#define FILE_READ_ATTRIBUTES          0x00000080

/*
 * Write the attributes of the file
*/
#define FILE_WRITE_ATTRIBUTES         0x00000100

/**
 * For a directory, the right to list the contents of a the directory.
*/
#define FILE_LIST_DIRECTORY           0x0001

/**
 * For a directory, the right to create a file in the directory.
*/
#define FILE_ADD_FILE                 0x0002

/**
 * For a file object, the right to append data to the file. (For local files,
 * write operations will not overwrite existing data if this flag is specified
 * without FILE_WRITE_DATA.) For a directory object, the right to create a
 * subdirectory (FILE_ADD_SUBDIRECTORY).
*/
#define FILE_APPEND_DATA              0x0004

/**
 * For a directory, the right to create a subdirectory.
*/
#define FILE_ADD_SUBDIRECTORY         0x0004

/**
 * For a named pipe, the right to create a pipe.
*/
#define FILE_CREATE_PIPE_INSTANCE     0x0004

/**
 * For a native code file, the right to execute the file. This access right given
 * to scripts may cause the script to be executable, depending on the script
 * interpreter.
*/
#define FILE_EXECUTE                  0x0020

/**
 * For a directory, the right to traverse the directory. By default, users are
 * assigned the BYPASS_TRAVERSE_CHECKING privilege, which ignores the
 * FILE_TRAVERSE access right.
*/
#define FILE_TRAVERSE                 0x0020

/**
 * For a directory, the right to delete a directory and all the files it
 * contains, including read-only files.
*/
#define FILE_DELETE_CHILD             0x0040






/**
 * FILE SHARE ACCESS
*/
#define FILE_SHARE_READ   0x1
#define FILE_SHARE_WRITE  0x2
#define FILE_SHARE_DELETE 0x4


/**
 * FILE CREATE DISPOSITION
*/

/**
 * If the file already exists, replace it with the given file. If it does not,
 * create the given file.
*/
#define FILE_SUPERSEDE     0x0

/**
 * If the file already exists, open it instead of create a new file. If it
 * does not, fail the request and do not create a new file.
*/
#define FILE_OPEN          0x1

/**
 * If the file already exists, fail the request and do not create or open
 * the given file. If it does not, create the given file.
*/
#define FILE_CREATE        0x2

/**
 * If the file already exists, open it. If it does not, create the given file.
*/
#define FILE_OPEN_IF       0x3

/**
 * If the file already exists, open it and overwrite it. If it does not, fail
 * the request.
*/
#define FILE_OVERWRITE     0x4

/**
 * If the file already exists, open it and overwrite it. If it does not,
 * create the given file.
*/
#define FILE_OVERWRITE_IF  0x5


/*
 * The file is a directory. Compatible CreateOptions flags are
 * FILE_SYNCHRONOUS_IO_ALERT, FILE_SYNCHRONOUS_IO_NONALERT,
 * FILE_WRITE_THROUGH, FILE_OPEN_FOR_BACKUP_INTENT, and
 * FILE_OPEN_BY_FILE_ID. The CreateDisposition parameter must be set
 * to FILE_CREATE, FILE_OPEN, or FILE_OPEN_IF.
*/
#define FILE_DIRECTORY_FILE            0x00000001


/*
 * System services, file-system drivers, and drivers that write data to
 * the file must actually transfer the data to the file before any requested
 * write operation is considered complete.
*/
#define FILE_WRITE_THROUGH             0x00000002

/*
 * All access to the file will be sequential.
*/
#define FILE_SEQUENTIAL_ONLY           0x00000004


/*
 * The file cannot be cached or buffered in a driver's internal buffers.
 * This flag is incompatible with the DesiredAccess parameter's
 * FILE_APPEND_DATA flag.
*/
#define FILE_NO_INTERMEDIATE_BUFFERING 0x00000008

/*
 * All operations on the file are performed synchronously. Any waits on
 * behalf of the caller is subject to premature termination from alerts.
 * This flag also causes the I/O system to maintain the file-position pointer.
 * If this flag is set, the SYNCHRONIZE flag must be set in the
 * DesiredAccess parameter.
 *
*/
#define FILE_SYNCHRONOUS_IO_ALERT      0x00000010

/*
 * All operations on the file are performed synchronously. Waits in the
 * system that synchronize I/O queueing and completion are not subject
 * to alerts. This flag also causes the I/O system to maintain the
 * file-position context. If this flag is set, the SYNCHRONIZE flag
 * must be set in the DesiredAccess parameter.
*/
#define FILE_SYNCHRONOUS_IO_NONALERT   0x00000020


/*
 * The file is not a directory. The file to open can represent a data
 * file; a logical, virtual, or physical device; or a volume.
*/
#define FILE_NON_DIRECTORY_FILE        0x00000040

/*
 * Create a tree connection for this file in order to open it over
 * the network. This flag is not used by device and intermediate
 * drivers.
*/
#define FILE_CREATE_TREE_CONNECTION    0x00000080

/*
 * Complete this operation immediately with an alternate success code
 * of STATUS_OPLOCK_BREAK_IN_PROGRESS if the target file is oplocked,
 * rather than blocking the caller's thread. If the file is oplocked,
 * another caller already has access to the file. This flag is not
 * used by device and intermediate drivers.
*/
#define FILE_COMPLETE_IF_OPLOCKED      0x00000100

/*
 * If the extended attributes (EAs) for an existing file being
 * opened indicate that the caller must understand EAs to properly
 * interpret the file, NtCreateFile should return an error. This
 * flag is irrelevant for device and intermediate drivers.
*/
#define FILE_NO_EA_KNOWLEDGE           0x00000200

/*
 * Access to the file can be random, so no sequential read-ahead
 * operations should be performed by file-system drivers or by the
 * system.
*/
#define FILE_RANDOM_ACCESS             0x00000800

/*
 * The system deletes the file when the last handle to the file is
 * passed to NtClose. If this flag is set, the DELETE flag must be
 * set in the DesiredAccess paraemter.
*/
#define FILE_DELETE_ON_CLOSE           0x00001000

/*
 * The file name that is specified by the ObjectAttributes parameter
 * includes a binary 8-byte or 16-byte file reference number or object
 * ID for the file, depending on the file system. Optionally, a device
 * name followed by a backslash character may proceed these binary
 * values. An example is:
 *	\??\C:\<FileID>\device\HardDiskVolume1\<ObjectID> 
 * where FileID is 8 bytes and ObjectID is 16 bytes. On NTFS, this can
 * be a 8-byte or 16-byte reference number or object ID. A 16-byte
 * reference number, is the same as an 8-byte number padded with zeros.
*/
#define FILE_OPEN_BY_FILE_ID           0x00002000

/*
 * The file is being opened for backup intent. Therefore, the system
 * should check for certain access rights and grant the caller the
 * appropriate access to the file - before checking the DesiredAccess
 * parameter against the file's security descriptor. This flag not
 * used by device and intermediate drivers.
*/
#define FILE_OPEN_FOR_BACKUP_INTENT    0x00004000

/*
 * The file is being opened and an opportunistic lock (oplock) on the
 * file is being requested as a single atomic operation. The file
 * system checks for oplocks before it performs the create operation,
 * and will fail the create with a return code of
 * STATUS_CANNOT_BREAK_OPLOCK if the result would be to break an
 * existing oplock. This flag is available starting with Windows 7
 * and Windows Server 2008 R2.
*/
#define FILE_OPEN_REQUIRING_OPLOCK     0x00010000

/*
 * The client opening the file or device is session aware and per
 * session access is validated if necessary. This flag is available
 * starting with Windows 8.
*/
#define FILE_SESSION_AWARE             0x00040000

/*
 * This flag allows an application to request a Filter opportunistic
 * lock (oplock) on the file is being requested as a single atomic
 * operation. The file system checks for oplocks before it performs
 * the create operation, and will fail the create with a return code
 * of STATUS_CANNOT_BREAK_OPLOCK if the result would be to break an
 * existing oplock. This flag is available starting with Windows 7
 * and Windows Server 2008 R2.
*/
#define FILE_RESERVE_OPFILTER          0x00100000

/*
 * Open a file with a reparse point and bypass normal reparse point
 * processing for the file.
*/
#define FILE_OPEN_REPARSE_POINT        0x00200000





/**
 * FILE ATTRIBUTES
*/
#define FILE_ATTRIBUTE_READONLY   0x1
#define FILE_ATTRIBUTE_HIDDEN     0x2
#define FILE_ATTRIBUTE_SYSTEM     0x4
#define FILE_ATTRIBUTE_DIRECTORY  0x10
#define FILE_ATTRIBUTE_ARCHIVE    0x20
#define FILE_ATTRIBUTE_DEVICE     0x40
#define FILE_ATTRIBUTE_NORMAL     0x80
#define FILE_ATTRIBUTE_TEMPORARY  0x100
#define FILE_ATTRIBUTE_ENCRYPED   0x4000
#define FILE_ATTRIBUTE_COMPRESSED 0x800

// The handle that identifies a directory
#define FILE_ATTRIBUTE_VIRTUAL    0x10000





#define FILE_GENERIC_EXECUTE\
	(FILE_EXECUTE |\
	FILE_READ_ATTRIBUTES |\
	STANDARD_RIGHTS_EXECUTE |\
	SYNCHRONIZE)

#define FILE_GENERIC_READ\
	(FILE_READ_ATTRIBUTES |\
	FILE_READ_DATA |\
	FILE_READ_EA |\
	STANDARD_RIGHTS_READ |\
	SYNCHRONIZE)

#define FILE_GENERIC_WRITE\
	(FILE_APPEND_DATA |\
	FILE_WRITE_ATTRIBUTES |\
	FILE_WRITE_DATA |\
	FILE_WRITE_EA |\
	STANDARD_RIGHTS_WRITE |\
	SYNCHRONIZE)

#define FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)



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


typedef void (__stdcall *PIO_APC_ROUTINE)
	(void *, struct _IO_STATUS_BLOCK *, unsigned long); 

typedef struct _CSR_API_MSG {
	long NOT_COMPLETE;
/*
	PORT_MESSAGE h;
	union {

	};
*/
} CSR_API_MSG;


#define MEM_EXTENDED_PARAMETER_TYPE_BITS 8

// TODO (Garrett) Finish defining this struct
typedef struct _MEM_EXTENDED_PARAMETER {
	struct {
		DWORD64 Type: MEM_EXTENDED_PARAMETER_TYPE_BITS;
		DWORD64 Reserved: 64 - MEM_EXTENDED_PARAMETER_TYPE_BITS;
	} DUMMYSTRUCTNAME;
	union {
		DWORD64 ULong64;
		void *Pointer;
		size_t Size;
		void *Handle;
		unsigned int ULong;
	} DUMMYUNIONNAME;
} MEM_EXTENDED_PARAMETER, *PMEM_EXTENDED_PARAMETER;


typedef struct _CLIENT_ID {
	void *ProcessHandle;
	void *ThreadHandle;
} CLIENT_ID;




typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;



typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation
} SECTION_INFORMATION_CLASS;



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



typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation                         = 1,
    FileFullDirectoryInformation,                   // 2
    FileBothDirectoryInformation,                   // 3
    FileBasicInformation,                           // 4
    FileStandardInformation,                        // 5
    FileInternalInformation,                        // 6
    FileEaInformation,                              // 7
    FileAccessInformation,                          // 8
    FileNameInformation,                            // 9
    FileRenameInformation,                          // 10
    FileLinkInformation,                            // 11
    FileNamesInformation,                           // 12
    FileDispositionInformation,                     // 13
    FilePositionInformation,                        // 14
    FileFullEaInformation,                          // 15
    FileModeInformation,                            // 16
    FileAlignmentInformation,                       // 17
    FileAllInformation,                             // 18
    FileAllocationInformation,                      // 19
    FileEndOfFileInformation,                       // 20
    FileAlternateNameInformation,                   // 21
    FileStreamInformation,                          // 22
    FilePipeInformation,                            // 23
    FilePipeLocalInformation,                       // 24
    FilePipeRemoteInformation,                      // 25
    FileMailslotQueryInformation,                   // 26
    FileMailslotSetInformation,                     // 27
    FileCompressionInformation,                     // 28
    FileObjectIdInformation,                        // 29
    FileCompletionInformation,                      // 30
    FileMoveClusterInformation,                     // 31
    FileQuotaInformation,                           // 32
    FileReparsePointInformation,                    // 33
    FileNetworkOpenInformation,                     // 34
    FileAttributeTagInformation,                    // 35
    FileTrackingInformation,                        // 36
    FileIdBothDirectoryInformation,                 // 37
    FileIdFullDirectoryInformation,                 // 38
    FileValidDataLengthInformation,                 // 39
    FileShortNameInformation,                       // 40
    FileIoCompletionNotificationInformation,        // 41
    FileIoStatusBlockRangeInformation,              // 42
    FileIoPriorityHintInformation,                  // 43
    FileSfioReserveInformation,                     // 44
    FileSfioVolumeInformation,                      // 45
    FileHardLinkInformation,                        // 46
    FileProcessIdsUsingFileInformation,             // 47
    FileNormalizedNameInformation,                  // 48
    FileNetworkPhysicalNameInformation,             // 49
    FileIdGlobalTxDirectoryInformation,             // 50
    FileIsRemoteDeviceInformation,                  // 51
    FileUnusedInformation,                          // 52
    FileNumaNodeInformation,                        // 53
    FileStandardLinkInformation,                    // 54
    FileRemoteProtocolInformation,                  // 55

        //
        //  These are special versions of these operations (defined earlier)
        //  which can be used by kernel mode drivers only to bypass security
        //  access checks for Rename and HardLink operations.  These operations
        //  are only recognized by the IOManager, a file system should never
        //  receive these.
        //

    FileRenameInformationBypassAccessCheck,         // 56
    FileLinkInformationBypassAccessCheck,           // 57

        //
        // End of special information classes reserved for IOManager.
        //

    FileVolumeNameInformation,                      // 58
    FileIdInformation,                              // 59
    FileIdExtdDirectoryInformation,                 // 60
    FileReplaceCompletionInformation,               // 61
    FileHardLinkFullIdInformation,                  // 62
    FileIdExtdBothDirectoryInformation,             // 63
    FileDispositionInformationEx,                   // 64
    FileRenameInformationEx,                        // 65
    FileRenameInformationExBypassAccessCheck,       // 66
    FileDesiredStorageClassInformation,             // 67
    FileStatInformation,                            // 68
    FileMemoryPartitionInformation,                 // 69
    FileStatLxInformation,                          // 70
    FileCaseSensitiveInformation,                   // 71
    FileLinkInformationEx,                          // 72
    FileLinkInformationExBypassAccessCheck,         // 73
    FileStorageReserveIdInformation,                // 74
    FileCaseSensitiveInformationForceAccessCheck,   // 75

    FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;




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


typedef struct _FILE_OBJECT {
	short Type;
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
} FILE_OBJECT, *PFILE_OBJECT;
*/




#define IO_COMPLETION_QUERY_STATE    0x01
#define IO_COMPLETION_MODIFY_STATE   0x02
#define IO_COMPLETION_ALL_ACCESS \
(STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x03)



/**
 * Create IO Completion object. IO Completion Object is used for waiting on
 * pending IO operation (reading or writing) in multi-process file access. It
 * contains more information about IO operation than synchronization event or
 * APC Routine.
 * Count: Number of threads accessing File Object associated with IO Completion.
 * If Zero, system reserves memory for number of threads equal to current
 * number of processes. NumberOfConcurrentThreads
*/
unsigned long __stdcall NtCreateIoCompletion
	(void **IoCompletionHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	unsigned long Count);



/**
 * Opens and existing IO Completion object. IO Completion must've been created
 * as a named object.
*/
unsigned long __stdcall NtOpenIoCompletion
	(void **IoCompletionHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes);



/**
 * RequiredLength: Optionally receives required length of buffer
*/
unsigned long __stdcall NtQueryIoCompletion
	(void *IoCompletionHandle,
	IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
	void *IoCompletionInformation,
	unsigned long InformationBufferLength,
	unsigned long *RequiredLength);

/**
 * Increments pending IO counter in IO Completion object. It can be used to
 * manual finish IO operation.
 * CompletionKey: User's defined key received by NtRemoveIoCompletion function
 * NumberOfBytesTransferred: Number of bytes transfered in manually finished
 * 	IO operation.
*/
unsigned long __stdcall NtSetIoCompletion
	(void *IoCompletionHandle,
	unsigned long CompletionKey,
	IO_STATUS_BLOCK *IoStatusBlock,
	unsigned long CompletionStatus,
	unsigned long NumberOfBytesTransferred);


unsigned long __stdcall NtSetIoCompletionEx
	(void *IoCompletionHandle,
	void *IoCompletionPacketHandle,
	void *KeyContext,
	void *ApcContext,
	unsigned long IoStatus,
	size_t IoStatusInformation);

/**
 * One of waiting calls and it's finished when at least one completion record
 * will be available in specified IO Completion object. Records are added when
 * I/O operation is finished, but previously File object have to been
 * associated with Io Completion object.
 * Assocation between File and Io Completion objects is made by a call to
 * NtSetInformationFile with FileCompletionInformation information class.
 * Additionally every assocation have to have unique Key defined. This
 * functionality allows to use one Io Completion object with different File
 * objects.
 * Every one File object can have only one Io Completion associated with it.
 * I/O operations won't be appended to Io Completion object except file
 * operations will be called with non-zero value in ApcContext parameters.
 *
 * IoCompletionHandle: HANDLE to previously created or opened IO Completion object.
 * CompletionKey: Receives completion Key informing about File object who
 * 	finishes I/O.
 * CompletionValue: Value of ApcContext file operation parameter. Informs about
 * 	operation finished.
 * IoStatusBlock: Io status of finished operation.
 * Timeout: Optionally pointer to time out value.
*/
unsigned long __stdcall NtRemoveIoCompletion
	(void *IoCompletionHandle,
	unsigned long *CompletionKey,
	unsigned long *CompletionValue,
	IO_STATUS_BLOCK *IoStatusBlock,
	LARGE_INTEGER *Timeout);


unsigned long __stdcall NtRemoveIoCompletionEx
	(void *IoCompletionHandle,
	FILE_IO_COMPLETION_INFORMATION *IoCompletionInformation,
	unsigned long Count,
	unsigned long *NumEntiesRemoved,
	LARGE_INTEGER *Timeout,
	bool Alertable);


unsigned long __stdcall NtCreateWaitCompletionPacket
	(void **WaitCompletionPacketHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes);


unsigned long __stdcall NtAssociateWaitCompletionPacket
	(void *WaitCompletionPacketHandle,
	void *IoCompletionHandle,
	void *TargetObjectHandle,
	void *KeyContext,
	void *ApcContext,
	unsigned long IoStatus,
	size_t IoStatusInformation,
	bool *AlreadySignaled);




unsigned long __stdcall NtCreateSection
	(void **SectionHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	LARGE_INTEGER *MaximumSize,
	unsigned long SectionPageProtection,
	unsigned long AllocationAttributes,
	void *FileHandle);

unsigned long __stdcall NtCreateSectionEx
	(void **SectionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	LARGE_INTEGER *MaximumSize,
	unsigned long SectionPageProtection,
	unsigned long AllocationAttributes,
	void *FileHandle,
	MEM_EXTENDED_PARAMETER *ExtendedParameters,
	unsigned long ExtendedParametersCount);

unsigned long __stdcall NtMapViewOfSection
	(void *SectionHandle,
	void *ProcessHandle,
	void **BaseAddress,
	size_t ZeroBits,
	size_t CommitSize,
	LARGE_INTEGER *SectionOffset,
	size_t *ViewSize,
	SECTION_INHERIT InheritDisposition,
	unsigned long AllocationType,
	unsigned long Win32Protect);

unsigned long __stdcall NtQuerySection
	(void *SectionHandle,
	SECTION_INFORMATION_CLASS InformationClass,
	void *InformationBuffer,
	unsigned long InformationBufferSize,
	unsigned long *ResultLength);


unsigned long __stdcall NtUnmapViewOfSection
	(void *ProcessHandle,
	void *BaseAddress);

unsigned long __stdcall NtOpenSection
	(void **SectionHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes);

unsigned long __stdcall NtUnmapViewOfSectionEx
	(void *ProcessHandle,
	void *BaseAddress,
	unsigned long Flags);

unsigned long __stdcall NtExtendSection
	(void *SectionHandle,
	LARGE_INTEGER *NewSectionSize);



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


typedef struct _PEB_LDR_DATA
{
	char Reserved1[8];
	void *Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA;


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


typedef struct _RTL_USER_PROCESS_PARAMETERS
{
/*
	char Reserved1[16];
	void * Reserved2[10];
*/
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
	wchar_t *Environment;
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


typedef struct _PEB_FREE_BLOCK
{
	struct _PEB_FREE_BLOCK *Next;
	unsigned long Size;
} PEB_FREE_BLOCK;


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




typedef struct _PS_ATTRIBUTE {
	unsigned long Attribute;
	size_t Size;
	union {
		unsigned long Value;
		void *ValuePtr;	
	};
	size_t *ReturnLength;
} PS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
	size_t TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;



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



// Define 128-bit 16-byte aligned xmm register type
typedef struct _M128A {
	unsigned long long Low;
	long long High;
} M128A, *PM128A;

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



#define CREATE_SUSPENDED  0x0004
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







#define PS_REQUEST_BREAKAWAY 0x01
#define PS_NO_DEBUG_INHERIT  0x02
#define PS_INHERIT_HANDLES   0x04
#define PS_UNKNOWN_VALUE     0x08

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





unsigned long __stdcall NtQuerySystemInformation
	(SYSTEM_INFORMATION_CLASS SystemInformationClass,
	void *SystemInformation,
	unsigned long SystemInformationLength,
	unsigned long *ReturnLength);



/**
 * Required to query the values of a registry key.
*/
#define KEY_QUERY_VALUE        0x0001

/**
 * Required to create, delete, or set a registry value.
*/
#define KEY_SET_VALUE          0x0002

/**
 * Required to create a subkey of a registry key.
*/
#define KEY_CREATE_SUB_KEY     0x0004

/**
 * Required to enumerate the subkeys of a registry key.
*/
#define KEY_ENUMERATE_SUB_KEYS 0x0008

/**
 * Required to request change notifications for a registry key or
 * for subkeys of a registry key.
*/
#define KEY_NOTIFY             0x0010

#define KEY_CREATE_LINK        0x0020
#define KEY_WOW64_32KEY        0x0200
#define KEY_WOW64_64KEY        0x0100
#define KEY_ALL_ACCESS

#define KEY_WRITE
#define KEY_READ
#define KEY_EXECUTE  KEY_READ    


// Creates a new registry key or opens an existing one.
unsigned long __stdcall NtCreateKey(
	void **KeyHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	unsigned long TitleIndex,
	UNICODE_STRING *Class,
	unsigned long CreateOptions,
	unsigned long *Disposition);


unsigned long __stdcall NtOpenKey(
	void **KeyHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes);


unsigned long __stdcall NtOpenKeyEx(
	void **KeyHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	unsigned long OpenOptions);


// Creates or replaces a registry key's value entry
unsigned long __stdcall NtSetValueKey(
	void *KeyHandle,
	UNICODE_STRING *ValueName,
	unsigned long TitleIndex,
	unsigned long Type,
	void *Data,
	unsigned long DataSize);


typedef enum _KEY_SET_INFORMATION_CLASS
{
	KeyWriteTimeInformation,
	KeyWow64FlagsInformation,
	KeyControlFlagsInformation,
	KeySetVirtualizationInformation,
	KeySetDebugInformation,
	KeySetHandleTagsInformation,
	KeySetLayerInformation,
} KEY_SET_INFORMATION_CLASS;

unsigned long __stdcall NtSetInformationKey(
	void *KeyHandle,
	KEY_SET_INFORMATION_CLASS KeySetInformationClass,
	void *KeySetInformation,
	unsigned long *KeySetInformationLength);


typedef enum _KEY_VALUE_INFORMATION_CLASS
{
	KeyValueBasicInformation,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	KeyValueLayerInformation
} KEY_VALUE_INFORMATION_CLASS;


unsigned long __stdcall NtQueryValueKey(
	void *KeyHandle,
	UNICODE_STRING *ValueName,
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	void *KeyValueInformation,
	unsigned long Length,
	unsigned long *ResultLength);

unsigned long __stdcall NtEnumerateValueKey(
	void *KeyHandle,
	unsigned long Index,
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	void *KeyValueInformation,
	unsigned long *Length,
	unsigned long *ResultLength);



typedef struct _KEY_CACHED_INFORMATION
{
	LARGE_INTEGER LastWriteTime;
	unsigned long TitleIndex;
	unsigned long SubKeys;
	unsigned long MaxNameLen;
	unsigned long Values;
	unsigned long MaxValueNameLen;
	unsigned long MaxValueDataLen;
	unsigned long NameLength;
} KEY_CACHED_INFORMATION;



typedef struct _KEY_BASIC_INFORMATION
{
	LARGE_INTEGER LastWriteTime;
	unsigned long TitleIndex;
	unsigned long NameLength;
	wchar_t Name[1];
} KEY_BASIC_INFORMATION;


typedef enum _KEY_INFORMATION_CLASS
{
	KeyBasicInformation,
	KeyNodeInformation,
	KeyFullInformation,
	KeyNameInformation,
	KeyCachedInformation,
	KeyFlagsInformation,
	KeyVirtualizationInformation,
	KeyHandleTagsInformation,
	KeyTrustInformation,
	KeyLayerInformation,
} KEY_INFORMATION_CLASS;

unsigned long __stdcall NtQueryKey(
	void *KeyHandle,
	KEY_INFORMATION_CLASS KeyInformationClass,
	void *KeyInformation,
	unsigned long Length,
	unsigned long *ResultLength);


unsigned long __stdcall NtEnumerateKey(
	void *KeyHandle,
	unsigned long Index,
	KEY_INFORMATION_CLASS KeyInformationClass,
	void *KeyInformation,
	unsigned long Length,
	unsigned long *ResultLength);

unsigned long __stdcall NtDeleteKey(void *KeyHandle);

unsigned long __stdcall NtDeleteValueKey(
	void *KeyHandle,
	UNICODE_STRING *ValueName);


// Allows a driver to request notification when a registry key changes.
unsigned long __stdcall NtNotifyChangeKey(
	void *KeyHandle,
	void *Event,
	PIO_APC_ROUTINE ApcRoutine,
	void *ApcContext,
	IO_STATUS_BLOCK *IoStatusBlock,
	unsigned long CompletionFilter,
	bool WatchTree,
	void *Buffer,
	unsigned long BufferSize,
	bool Asynchronous);




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

unsigned long __stdcall NtDelayExecution
	(bool Alertable,
	LARGE_INTEGER *DelayInterval);

unsigned long __stdcall NtAlertThread(void *ThreadHandle);


unsigned long __stdcall NtResumeThread
	(void *ThreadHandle,
	unsigned long *SuspendCount);


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

typedef enum _EVENT_TYPE
{
	NotificationEvent,
	SynchronizationEvent
} EVENT_TYPE;

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



unsigned long __stdcall NtCreateFile(
	void **FileHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	IO_STATUS_BLOCK *IoStatusBlock,
	LARGE_INTEGER *AllocationSize,
	unsigned long FileAttributes,
	unsigned long ShareAccess,
	unsigned long CreateDisposition,
	unsigned long CreateOptions,
	void *EaBuffer,
	unsigned long EaLength);


unsigned long __stdcall NtDeleteFile(
	OBJECT_ATTRIBUTES *ObjectAttributes);


unsigned long __stdcall NtOpenFile(
	void **FileHandlePtr,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	IO_STATUS_BLOCK *IoStatusBlock,
	unsigned long ShareAccess,
	unsigned long OpenOptions);


unsigned long __stdcall NtClose(void *Handle);


unsigned long __stdcall NtOpenDirectoryObject(
	void **DirectoryHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *pObjectAttr);


unsigned long __stdcall NtSetInformationFile(
	void *FileHandle,
	IO_STATUS_BLOCK *IoStatusBlock,
	void *FileInformation,
	unsigned long Length,
	FILE_INFORMATION_CLASS FileInformationClass);



typedef struct _FILE_TIME_INFORMATION {
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
} FILE_TIME_INFORMATION;


typedef struct _FILE_BASIC_INFORMATION {
	FILE_TIME_INFORMATION FileTime;
	unsigned long FileAttributes;
} FILE_BASIC_INFORMATION;


typedef struct _FILE_DIRECTORY_INFORMATION {
	unsigned long NextEntryOffset;
	unsigned long FileIndex;
	FILE_TIME_INFORMATION FileTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	unsigned long FileAttributes;

/**
 * The length of the file in bytes. To get the number of chars divide this
 * value by 2 or just shift bits to the right by 1
*/
	unsigned long FileNameLength;
	unsigned short FileName[1];
} FILE_DIRECTORY_INFORMATION;


typedef struct _FILE_FULL_DIR_INFORMATION {
	unsigned long NextEntryOffset;
	unsigned long FileIndex;
	FILE_TIME_INFORMATION FileTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	unsigned long FileAttributes;
	unsigned long FileNameLength;
	unsigned long EaSize;
	wchar_t FileName[1];
} FILE_FULL_DIR_INFORMATION;


typedef struct _FILE_BOTH_DIR_INFORMATION {
	unsigned long NextEntryOffset;
	unsigned long FileIndex;
	FILE_TIME_INFORMATION FileTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AlloctionSize;
	unsigned long FileAttributes;
	unsigned long FileNameLength;
	unsigned long EaSize;
	char ShortNameLength;
	unsigned short ShortName[12];
	unsigned short FileName[1];
} FILE_BOTH_DIR_INFORMATION;




/**
 * Used to enumerate entries (files or directories) placed into file container
 * object (directory).
*/
unsigned long __stdcall NtQueryDirectoryFile(
	void *FileHandle,
	void *Event,
	PIO_APC_ROUTINE ApcRoutine,
	void *ApcContext,
	IO_STATUS_BLOCK *IoStatusBlock,
	void *FileInfo,
	unsigned long Length,
	FILE_INFORMATION_CLASS FileInfoClass,
	bool ReturnSingleEntry,
	UNICODE_STRING *Filter,
	bool RestartScan);




/**
 * The scan will start at the first entry in the directory. If this flag is
 * not set, the scan will resume from where the last query ended.
*/
#define SL_RESTART_SCAN 0x001

/**
 * Normally the return buffer is packed with as many matching directory entries
 * that fit. If this flag is set, the file system will return only one directory
 * entry at a time. This does make the operation less efficient.
*/
#define SL_RETURN_SINGLE_ENTRY  0x002

/**
 * The scan should start at a specified indexed position in the directory. This
 * flag can only be set if you generate your own IRP_MJ_DIRECTORY_CONTROL_IRP;
 * the index is specified in the IRP. How the position is specified varies from
 * file system to file system.
*/
#define SL_INDEX_SPECIFIED 0x004

/**
 * Any file system filters that perform directory virtualization or just-in-time
 * expansion should simply pass the request through to the file system and
 * return entries that are currently on disk. Not all file systems support this
 * flag.
*/
#define SL_RETURN_ON_DISK_ENTRIES_ONLY  0x008


#define SL_NO_CURSOR_UPDATE_QUERY 0x0010


unsigned long __stdcall NtQueryDirectoryFileEx(
	void *FileHandle,
	void *Event,
	PIO_APC_ROUTINE ApcRoutine,

/**
 * An optional pointer to a caller-determined context area if the caller supplies
 * an APC or if an I/O completion object is associated with the file object. When
 * the operation completes, this context is passed to the APC, if one was
 * specified, or is included as part of the completion message that the I/O
 * Manager posts to the associated I/O completion object.
 * This parameter is optional and can be NULL. It must be NULL if ApcRoutine is
 * NULL and there is no I/O completion object associated with the file object.
*/
	void *ApcContext,
	IO_STATUS_BLOCK *IoStatusBlock,
	void *FileInformation,
	unsigned long Length,
	FILE_INFORMATION_CLASS FileInfoClass,
	unsigned long QueryFlags,
	UNICODE_STRING *Filter);




unsigned long __stdcall NtWriteFile(
	void *FileHandle,
	void *Event,
	PIO_APC_ROUTINE ApcRoutine,
	void *ApcContext,
	IO_STATUS_BLOCK *IoStatusBlock,
	void *Buffer,
	unsigned long Length,
	LARGE_INTEGER *ByteOffset,
	unsigned long *Key);

unsigned long __stdcall NtReadFile(
	void *FileHandle,
	void *Event,
	PIO_APC_ROUTINE ApcRoutine,
	void *ApcContext,
	IO_STATUS_BLOCK *IoStatusBlock,
	void *Buffer,
	unsigned long Length,
	LARGE_INTEGER *ByteOffset,
	unsigned long *Key);


unsigned long __stdcall NtCreateEvent(
	void **EventHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	unsigned long EventType,
	bool InitialState);


typedef struct _FILE_NAME_INFORMATION
{
	unsigned long FileNameLength;
	unsigned short FileName[1];
} FILE_NAME_INFORMATION;


unsigned long __stdcall NtQueryInformationFile(
	void *FileHandle,
	IO_STATUS_BLOCK *IoStatusBlock,
	void *FileInformation,
	unsigned long Length,
	unsigned int FileInformationClass);



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


unsigned long __stdcall NtTerminateProcess(
	void *ProcessHandle,
	unsigned long ExitStatus);

unsigned long __stdcall NtTerminateThread(
	void *Handle,
	unsigned long ExitStatus);



inline void * __stdcall NtCurrentProcess()
{
	return (void*)0xffffffff;
}

inline void * __stdcall NtCurrentThread()
{
	return (void*)0xfffffffe;
}


/**
 * This routine reserves, commits, or both, a region of pages within
 * the user-mode virtual address space of a specified process.
*/
unsigned long __stdcall NtAllocateVirtualMemory(
	void *ProcessHandle,
	void **BaseAddress,
	size_t ZeroBits, //ULONG_PTR
	size_t *RegionSize,
	unsigned long AllocationType,
	unsigned long Protect);


unsigned long __stdcall NtAllocateVirtualMemoryEx(
	void *ProcessHandle,
	void **BaseAddress,
	size_t *RegionSize,
	unsigned long AllocationType,
	unsigned long PageProtection,
	MEM_EXTENDED_PARAMETER *ExtendedParameters,
	unsigned long ExtendedParameterCount);



unsigned long __stdcall NtFreeVirtualMemory(
	void *ProcessHandle,
	void **BaseAddress,
	size_t *RegionSize,
	unsigned long FreeType);


unsigned long __stdcall NtProtectVirtualMemory(
	void *ProcessHandle,
	void **BaseAddress,

	/**
	 * A pointer to a variable that will receive the actual
	 * size in bytes of the protected region of pages. The intial
	 * value of this argument is rounded up to the next host page
	 * size boundary.
	*/
	unsigned long *RegionSize,

	unsigned long NewProtect,
	unsigned long *OldProtect);


/**
 * This function allocates nonpaged physical pages for the specified
 * subject process.
*/
unsigned long __stdcall NtAllocateUserPhysicalPages(
	void *ProcessHandle,
	void **NumberOfPages,
	void **UserPfnArray);



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



/**
 * Creates and opens the server end handle of the first instance of
 * a specific named pipe or another instance of an existing named pipe.
 */
unsigned long __stdcall NtCreateNamedPipeFile(

// Supplies a handle to the file on which the service is being performed.
	void **NamedPipeFileHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	IO_STATUS_BLOCK *IoStatusBlock,
	unsigned long SharedAccess,
	unsigned long CreateDisposition,

// Caller options for how to perform the create/open
	unsigned long CreateOptions,

// Mode in which to write the pipe
	bool WriteModeMessage,

// Mode in which to read the pipe
	bool ReadModeMessage,

// Specifies how the operation is to be completed
	bool NonBlocking,

// Maximum number of simultaneous instances of the named pipe.
	unsigned long MaxInstances,
	unsigned long InBufferSize,
	unsigned long OutBufferSize,
	LARGE_INTEGER *DefaultTimeout);




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

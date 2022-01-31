
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
 * FILE CreateDisposition 
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
 * FileAttributes
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





/**
 * Creates a new file or directory, or opens an existing file, device, directory, or
 * volume.
 */
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



unsigned long __stdcall NtDeleteFile(
	OBJECT_ATTRIBUTES *ObjectAttributes);


unsigned long __stdcall NtOpenFile(
	void **FileHandlePtr,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	IO_STATUS_BLOCK *IoStatusBlock,
	unsigned long ShareAccess,
	unsigned long OpenOptions);

unsigned long __stdcall NtSetInformationFile(
	void *FileHandle,
	IO_STATUS_BLOCK *IoStatusBlock,
	void *FileInformation,
	unsigned long Length,
	FILE_INFORMATION_CLASS FileInformationClass);


typedef struct _FILE_NAME_INFORMATION
{
	unsigned long FileNameLength;
	unsigned short FileName[1];
} FILE_NAME_INFORMATION;



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



unsigned long __stdcall NtQueryInformationFile(
	void *FileHandle,
	IO_STATUS_BLOCK *IoStatusBlock,
	void *FileInformation,
	unsigned long Length,
	unsigned int FileInformationClass);



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



typedef struct _FILE_PIPE_LOCAL_INFORMATION
{
	unsigned long NamedPipeType;
	unsigned long NamedPipeConfiguration;
	unsigned long MaximumInstances;
	unsigned long CurrentInstances;
	unsigned long InboundQuota;
	unsigned long ReadDataAvailable;
	unsigned long OutboundQuota;
	unsigned long WriteQuotaAvailable;
	unsigned long NamedPipeState;
	unsigned long NamedPipeEnd;
} FILE_PIPE_LOCAL_INFORMATION;


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



#define CTL_CODE(DeviceType, Function, Method, Access) \
	((DeviceType<<16)|(Access<<14)|(Function<<2)|(Method))


#define METHOD_BUFFERED   0
#define METHOD_IN_DIRECT  1
#define METHOD_OUT_DIRECT 2
#define METHOD_NEITHER    3

#define FILE_ANY_ACCESS   0
#define FILE_READ_ACCESS  1
#define FILE_WRITE_ACCESS 2


/*
#define FSCTL_PIPE_ASSIGN_EVENT             0x00110000
#define FSCTL_PIPE_DISCONNECT               0x00110004
#define FSCTL_PIPE_LISTEN                   0x00110008
#define FSCTL_PIPE_PEEK                     0x0011400c
#define FSCTL_PIPE_QUERY_EVENT              0x00110010
#define FSCTL_PIPE_TRANSCEIVE               0x00118015
#define FSCTL_PIPE_WAIT                     0x00110018
#define FSCTL_PIPE_IMPERSONATE              0x0011001c
#define FSCTL_PIPE_SET_CLIENT_PROCESS       0x00110020
#define FSCTL_PIPE_QUERY_CLIENT_PROCESS     0x00110024
#define FSCTL_PIPE_GET_PIPE_ATTRIBUTE       0x00110028
#define FSCTL_PIPE_SET_PIPE_ATTRIBUTE       0x0011002c
#define FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE 0x00110030
#define FSCTL_PIPE_SET_CONNECTION_ATTRIBUTE 0x00110034
#define FSCTL_PIPE_SET_HANDLE_ATTRIBUTE     0x0011003c
#define FSCTL_PIPE_FLUSH                    0x00118040
#define FSCTL_PIPE_INTERNAL_READ            0x00115ff4
#define FSCTL_PIPE_INTERNAL_WRITE           0x00119ff8
#define FSCTL_PIPE_INTERNAL_TRANSCEIVE      0x00119fff
#define FSCTL_PIPE_INTERNAL_READ_OVFLOW     0x00116000
*/




#define FSCTL_PIPE_ASSIGN_EVENT             CTL_CODE(FILE_DEVICE_NAMED_PIPE,    0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_DISCONNECT               CTL_CODE(FILE_DEVICE_NAMED_PIPE,    1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_LISTEN                   CTL_CODE(FILE_DEVICE_NAMED_PIPE,    2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_PEEK                     CTL_CODE(FILE_DEVICE_NAMED_PIPE,    3, METHOD_BUFFERED, FILE_READ_DATA)
#define FSCTL_PIPE_QUERY_EVENT              CTL_CODE(FILE_DEVICE_NAMED_PIPE,    4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_TRANSCEIVE               CTL_CODE(FILE_DEVICE_NAMED_PIPE,    5, METHOD_BUFFERED, \
	FILE_READ_DATA | FILE_WRITE_DATA)
#define FSCTL_PIPE_WAIT                     CTL_CODE(FILE_DEVICE_NAMED_PIPE,    6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_IMPERSONATE              CTL_CODE(FILE_DEVICE_NAMED_PIPE,    7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_SET_CLIENT_PROCESS       CTL_CODE(FILE_DEVICE_NAMED_PIPE,    8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_QUERY_CLIENT_PROCESS     CTL_CODE(FILE_DEVICE_NAMED_PIPE,    9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_GET_PIPE_ATTRIBUTE       CTL_CODE(FILE_DEVICE_NAMED_PIPE,   10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_SET_PIPE_ATTRIBUTE       CTL_CODE(FILE_DEVICE_NAMED_PIPE,   11, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE CTL_CODE(FILE_DEVICE_NAMED_PIPE,   12, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_SET_CONNECTION_ATTRIBUTE CTL_CODE(FILE_DEVICE_NAMED_PIPE,   13, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_SET_HANDLE_ATTRIBUTE     CTL_CODE(FILE_DEVICE_NAMED_PIPE,   15, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_FLUSH                    CTL_CODE(FILE_DEVICE_NAMED_PIPE,   16, METHOD_BUFFERED, FILE_WRITE_DATA)

#define FSCTL_PIPE_INTERNAL_READ            CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2045, METHOD_BUFFERED, FILE_READ_DATA)
#define FSCTL_PIPE_INTERNAL_WRITE           CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2046, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FSCTL_PIPE_INTERNAL_TRANSCEIVE      CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2047, METHOD_NEITHER, \
	FILE_READ_DATA | FILE_WRITE_DATA)
#define FSCTL_PIPE_INTERNAL_READ_OVFLOW     CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2048, METHOD_BUFFERED, FILE_READ_DATA)





/*
 * Send a control code directly to a specified file system or file system
 * filter driver, causing the corresponding driver to perform the specified
 * action.
 */

unsigned long __stdcall NtFsControlFile(
	void *FileHandle,
	void *Event,
	PIO_APC_ROUTINE ApcRoutine,
	void *ApcContext,
	IO_STATUS_BLOCK *IoStatusBlock,
	unsigned long FsControlCode,
	void *InputBuffer,
	unsigned long InputBufferLength,
	void *OutputBuffer,
	unsigned long OutputBufferLength);




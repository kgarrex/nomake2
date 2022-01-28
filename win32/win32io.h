
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



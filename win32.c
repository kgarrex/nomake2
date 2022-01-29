struct WinObject
{
	void *Handle;
	ACCESS_MASK Access;
};


struct WinFile
{
	void *fileHandle;
	void *dirHandle;
	void *fileMap;
};


struct WinDir
{
	struct WinObject Object;
	void *event;
	//void *apc_routine;

	void *parentDirHandle;

	void *fileDataBlock;
	unsigned long fileDataBlockSize;

	char *path;
	unsigned int pathLength;

	void *context;

	bool (*traverseFiles)
		(void *ctx, unsigned long length, wchar_t *filename);
	bool (*traverseDirs)
		(void *ctx, unsigned long length, wchar_t *dirname);

};


#define bitsSet(bits, mask) ((bits | ~mask) == ~0)
#define bitsClear(bits, mask) ((bits & mask) == 0)


bool __stdcall hasAccess(void *handle, ACCESS_MASK access)
{
	unsigned long status;
	IO_STATUS_BLOCK ioStatusBlock;
	FILE_ACCESS_INFORMATION fa;

	status = NtQueryInformationFile(
		handle,
		&ioStatusBlock,
		&fa,
		sizeof(fa),
		FileAccessInformation);
	if(status > 0)
	{
		// error: could not get access info
		return false;
	}

	return bitsSet(fa.Access.mask, access.mask);
}


void * __stdcall grantObjectAccess(void *handle, ACCESS_MASK access)
{
	unsigned long status;
	void *newHandle;

	status = NtDuplicateObject(
		NtCurrentProcess(),
		handle,
		NtCurrentProcess(),
		&newHandle,
		access,
		0,
		DUPLICATE_SAME_ATTRIBUTES |
		DUPLICATE_CLOSE_SOURCE);
	if(status > 0)
	{
		// error: Could not duplicate object
		LogMessageW(L"NtDuplicateObject failed: 0x%1!x!\n", status);
		return 0;
	}

	return newHandle;
}


bool __stdcall revokeObjectAccess(void *handle)
{
	return false;
}



#define MIN_FILE_DATA_BLOCK_SIZE  256

void * __stdcall getFileDataBlock(unsigned long *size)
{
	void *block = 0;

	if(*size < MIN_FILE_DATA_BLOCK_SIZE) return 0;

	// allocate memory here to hold directory structures

	while(!(block = _alloc(*size)))
	{
		*size >>= 1;
		if(*size < MIN_FILE_DATA_BLOCK_SIZE) return 0;
	}

	return block;
}


void __stdcall getDirectoryDirs_apcRoutine(
	struct WinDir *Dir,
	IO_STATUS_BLOCK *IoStatusBlock,
	unsigned long Reserved)
{
	FILE_DIRECTORY_INFORMATION *info;
	unsigned long fileCount = 0;
	int result;

	info = Dir->fileDataBlock;

	LogMessageW(L"INFORMATION: %1!u!| IO STATUS: 0x%2!x!\n",
		IoStatusBlock->Information,
		IoStatusBlock->DUMMYUNIONNAME.Status);


	//LogMessageW(L"File Attributes: 0x%1!x!\n", info->FileAttributes);
	if(info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		fileCount++;
		result = Dir->traverseDirs(Dir->context,
			info->FileNameLength >> 1, info->FileName);
	}

loop:
	if(info->NextEntryOffset == 0) return;
	if(result == false) return;
	(char*)info += info->NextEntryOffset;
	goto loop;
}



void __stdcall getDirectoryFiles_apcRoutine(
	struct WinDir *Dir,
	IO_STATUS_BLOCK *IoStatusBlock,
	unsigned long Reserved)
{
	FILE_DIRECTORY_INFORMATION *info;
	unsigned long fileCount = 0;
	int result;

	info = Dir->fileDataBlock;


	LogMessageW(L"INFORMATION: %1!u!| IO STATUS: 0x%2!x!\n",
		IoStatusBlock->Information,
		IoStatusBlock->DUMMYUNIONNAME.Status);

loop:

	//LogMessageW(L"File Attributes: 0x%1!x!\n", info->FileAttributes);
	if(info->FileAttributes & ~FILE_ATTRIBUTE_DIRECTORY)
	{
		fileCount++;
		result = Dir->traverseFiles(Dir->context,
			info->FileNameLength >> 1, info->FileName);
	}

	if(info->NextEntryOffset == 0) return;
	if(result == false) return;
	(char*)info += info->NextEntryOffset;
	goto loop;
}



void __stdcall traverseEngine(
	struct WinDir *Dir,
	PIO_APC_ROUTINE apcRoutine)
{
	unsigned long status;
	IO_STATUS_BLOCK ioStatusBlock = {0};
	LARGE_INTEGER timeout = {0};



	Dir->fileDataBlockSize = 8192;
	Dir->fileDataBlock = getFileDataBlock(&Dir->fileDataBlockSize);
	if(!Dir->fileDataBlock)
	{
		LogMessageW(L"Could not get file data block\n");
		return;
	}

loop:


	status = NtQueryDirectoryFile(
		Dir->Object.Handle,
		NULL,
		0, //getDirectoryFiles_apcRoutine,
		0, //&Dir,
		&ioStatusBlock,
		Dir->fileDataBlock,
		Dir->fileDataBlockSize,
		FileDirectoryInformation,
		false,
		0,
		false);
	if(status != STATUS_PENDING)
	{
		LogMessageW(L"NtQueryDirectoryFileEx failed: 0x%1!x!\n", status);
		return;
	}

	status = NtWaitForSingleObject(Dir->Object.Handle, true, 0);
	if(status > 0)
	{
		LogMessageW(L"NtWaitForSingleObject failed: 0x%1!x!\n", status);
		return;
	}

	// can check for no more files or a zero in size returned
	if(ioStatusBlock.DUMMYUNIONNAME.Status == STATUS_NO_MORE_FILES)
		goto exit_loop;

	apcRoutine(Dir, &ioStatusBlock, 0);
	goto loop;

exit_loop:

	return;
}


void __stdcall getDirectoryFiles(struct WinDir *Directory)
{
	unsigned long status;
	IO_STATUS_BLOCK ioStatusBlock = {0};
	ACCESS_MASK access;

	void *handle = Directory->Object.Handle;


/*
	FILE_ACCESS_INFORMATION accessInfo;
	accessInfo.AccessFlags.mask |= FILE_LIST_DIRECTORY;
	status = NtSetInformationFile(
		handle,
		&ioStatusBlock,
		&accessInfo,
		sizeof(accessInfo),
		FileAccessInformation);
	if(status > 0)
	{
		LogMessageW(L"Could not set access information: 0x%1!x!\n", status);
		return;
	}
*/


	if(!Directory->Object.Handle)
	{
		// open the file here
	}


	access.mask = FILE_LIST_DIRECTORY;
	if(!hasAccess(handle, access))
	{
		grantObjectAccess(handle, access);
	}

	traverseEngine(Directory, getDirectoryFiles_apcRoutine);
}


void __stdcall getDirectoryDirs(struct WinDir *Directory)
{
	unsigned long status;
	IO_STATUS_BLOCK ioStatusBlock = {0};
	ACCESS_MASK access;

	void *handle = Directory->Object.Handle;

	Directory->fileDataBlockSize = 8192;
	Directory->fileDataBlock = getFileDataBlock(&Directory->fileDataBlockSize);
	if(!Directory->fileDataBlock)
	{
		LogMessageW(L"Could not get file data block\n");
		return;
	}


	if(!Directory->Object.Handle)
	{
		// open the directory here
	}

	access.mask = FILE_LIST_DIRECTORY;
	if(!hasAccess(handle, access))
	{
		grantObjectAccess(handle, access);
	}

	traverseEngine(Directory, getDirectoryDirs_apcRoutine);
}



//void * __stdcall openDir(void *dirHandle, char *path, uint32_t length)
int __stdcall openDir(struct WinSystem *System, struct WinDir * Dir)
{
	unsigned long status;
	void *dirHandle;
	IO_STATUS_BLOCK ioStatusBlock;
	OBJECT_ATTRIBUTES objectAttributes = {0};
	UNICODE_STRING str;

	objectAttributes.SizeOf = sizeof(objectAttributes);
	if(Dir->parentDirHandle)
	{
		objectAttributes.RootDirectory = Dir->parentDirHandle;
	}

	wchar_t pathbuf[256];
	unsigned short wchar_length;

	wchar_length = str8to16(pathbuf, Dir->path, Dir->pathLength);
	str.Length = wchar_length;
	str.MaximumLength = 256 << 1;
	str.Buffer = pathbuf;
	objectAttributes.ObjectName = &str;
	
	Dir->Object.Access.mask = SYNCHRONIZE | FILE_LIST_DIRECTORY;
	status = NtCreateFile(
		&dirHandle,
		Dir->Object.Access,
		&objectAttributes,
		&ioStatusBlock,
		0,
		FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ,
		FILE_OPEN_IF, FILE_DIRECTORY_FILE, 0, 0);
	if(status > 0)
	{
		LogMessageW(L"NtCreateFile failed: 0x%1!x!\n", status);
		return 0;
	}

	Dir->Object.Handle = dirHandle;

	return 1;
}


int __stdcall closeDir(struct WinDir *Dir)
{
	NtClose(Dir->Object.Handle);
	return 1;
}



void * __stdcall win32CreateFile(void *dirHandle, char *path, uint32_t length)
{
	unsigned long status;
	void *fileHandle;
	IO_STATUS_BLOCK ioStatusBlock;
	OBJECT_ATTRIBUTES objectAttributes = {0};
	UNICODE_STRING str;
	ACCESS_MASK access;

	objectAttributes.SizeOf = sizeof(objectAttributes);
	if(dirHandle)
	{
		objectAttributes.RootDirectory = dirHandle;
	}

	wchar_t pathbuf[256];
	unsigned short wchar_length;

	wchar_length = str8to16(pathbuf, path, length);
	str.Length = wchar_length;
	str.MaximumLength = 256;
	str.Buffer = pathbuf;
	objectAttributes.ObjectName = &str;
	
	access.mask = 0;
	status = NtCreateFile(
		&fileHandle,
		access,
		&objectAttributes,
		&ioStatusBlock,
		0,
		FILE_ATTRIBUTE_NORMAL, 0,
		FILE_OPEN_IF, FILE_DIRECTORY_FILE, 0, 0);
	if(status > 0){
		LogMessageW(L"NtCreateFile failed: 0x%1!x!\n", status);
		return 0;
	}

	return fileHandle;
}



void * __stdcall win32OpenFile(void *dirHandle, char *path, uint32_t length)
{
	unsigned long status;
	void *fileHandle;
	IO_STATUS_BLOCK ioStatusBlock;
	OBJECT_ATTRIBUTES objectAttributes = {0};
	UNICODE_STRING str;
	ACCESS_MASK access;
	unsigned long shareAccess = 0;

	objectAttributes.SizeOf = sizeof(objectAttributes);
	if(dirHandle)
	{
		objectAttributes.RootDirectory = dirHandle;
	}

	wchar_t pathbuf[256];
	unsigned short wchar_length;

	wchar_length = str8to16(pathbuf, path, length);

	str.Length = wchar_length;
	str.MaximumLength = 256;
	str.Buffer = pathbuf;
	objectAttributes.ObjectName = &str;
	
	access.mask = FILE_READ_DATA;
	status = NtCreateFile(
		&fileHandle,
		access,
		&objectAttributes,
		&ioStatusBlock,
		0,
		FILE_ATTRIBUTE_NORMAL,
		shareAccess,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE,
		0, 0);
	if(status > 0){
		// error: cannot create file
		LogMessageW(L"NtCreateFile failed: 0x%1!x!\n", status);
		return 0;
	}

	return fileHandle;
}


bool __stdcall win32ReadFile(void *fileHandle, char buffer[], size_t *size)
{
	unsigned long status;
	void *eventHandle = 0;
	PIO_APC_ROUTINE apcRoutine = 0;
	void *apcContext = 0;
	IO_STATUS_BLOCK ioStatusBlock;
	LARGE_INTEGER byteOffset = {0};
	unsigned long key = 0;

	status = NtReadFile(
		fileHandle,
		eventHandle,
		apcRoutine,
		apcContext,
		&ioStatusBlock,
		buffer,
		*size,
		&byteOffset,
		&key);
	if(status > 0)
	{
		// error: cannot read file
		return false;
	}
	*size = (size_t)ioStatusBlock.Information;
	return true;
}


bool __stdcall win32WriteFile(void *fileHandle, char buffer[], size_t *size)
{
	unsigned long status;
	void *eventHandle = 0;
	PIO_APC_ROUTINE apcRoutine = 0;
	void *apcContext = 0;
	IO_STATUS_BLOCK ioStatusBlock;
	LARGE_INTEGER byteOffset = {0};
	unsigned long key = 0;

	status = NtWriteFile(
		fileHandle,
		eventHandle,
		apcRoutine,
		apcContext,
		&ioStatusBlock,
		buffer,
		*size,
		&byteOffset,
		&key);
	if(status > 0)
	{
		// error: cannot read file
		return false;
	}
	*size = (size_t)ioStatusBlock.Information;
	return true;
}


bool __stdcall win32FileMap(void *fileHandle)
{
	//NtCreateSection
	return false;
}



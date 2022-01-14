

bool __stdcall nm_dir_file_exists(nm_dir_t *dir, wchar_t *relative_path)
{
#if defined(NOMAKE_WINDOWS)
	return false;
#endif
}





// takes a utf8 directory path
nm_dir_t * __stdcall nm_dir_open(nm_app_t *app, char *path, size_t length)
{
	unsigned long status;
	void *directory;
	void *drive;

	nm_dir_t *dir = 0;


	if(!path) return 0;


	// allocate the directory structure here
	dir = nm_malloc( sizeof(nm_dir_t) );
	if(!dir) {
		return dir;
	}

	dir->app = app;
	dir->refCount = 0;


	// allocate the string here


	UNICODE_STRING str;
	ACCESS_MASK access;
	IO_STATUS_BLOCK ioStatusBlock;

	OBJECT_ATTRIBUTES oa = {0};
	oa.SizeOf = sizeof(oa);
	oa.Attributes = OBJ_CASE_INSENSITIVE;

/*
	RtlInitUnicodeString(&str, L"\\??\\C:");
	//RtlInitUnicodeString(&str, L"\\Device\\HarddiskVolume2");
	oa.ObjectName = &str;
	access.mask = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY;

	// I think this needs to be an NtOpenFile call
	status = NtOpenFile(&drive, access, &oa, &iosb,
		FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
	if(status > 0){
		LogMessageW(L"NtOpenFile failed: 0x%1!x!\n", status);
		return;
	}
*/
	

	// convert string to wchar_t then fill out UNICODE_STRING struct
	// we know that file paths can only contain ASCII characters
	wchar_t pathbuf[256];
	unsigned short wchar_length = 0; 

	wchar_length = str8to16(pathbuf, path, length);
	LogMessageW(L"path length: %1!d!\n", wchar_length/2);

	str.length = wchar_length;
	str.maximum_length = 256 * sizeof(wchar_t);
	str.buffer = pathbuf;

	LogMessageW(L"path: %1!.*s!\n", wchar_length/2, pathbuf);

	//RtlInitUnicodeString(&str, pathbuf);

	oa.SizeOf = sizeof(oa);
	//oa.RootDirectory = drive;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.ObjectName = &str;

	access.mask = SYNCHRONIZE
	//| FILE_TRAVERSE
	| FILE_LIST_DIRECTORY
	;
	//access.mask = FILE_LIST_DIRECTORY;

	unsigned long fileAttr = 0;
	unsigned long shareAccess = FILE_SHARE_READ;
	unsigned long createDisp = 0;
	unsigned long createOptions = 0;

	fileAttr = FILE_ATTRIBUTE_DIRECTORY;
	createDisp = FILE_OPEN_IF;
	createOptions = FILE_DIRECTORY_FILE
	//| FILE_SYNCHRONOUS_IO_NONALERT
	;

	status = NtCreateFile(
		&dir->handle,
		access,
		&oa,
		&ioStatusBlock,
		0,
		fileAttr,
		shareAccess,
		createDisp,
		createOptions,
		0, 0);
	if(status > 0){
		LogMessageW(L"NtCreateFile (nm_dir_open) failed: 0x%1!x!\n",
			status);
		return 0;
	}


	return dir;
}



bool __stdcall nm_dir_exists(char *path, size_t length)
{
	unsigned long status;

	OBJECT_ATTRIBUTES oa = {0};
	UNICODE_STRING str;

	wchar_t pathbuf[256];
	unsigned short wchar_length = 0;

	wchar_length = str8to16(pathbuf, path, length);

	str.length = wchar_length;
	str.maximum_length = 256;
	str.buffer = pathbuf;

	oa.SizeOf = sizeof(OBJECT_ATTRIBUTES);
	oa.Attributes = 0;
	oa.ObjectName = &str;


	//NtOpenFile();

	return false;
}


struct nm_dir_traverse_apc_routine_context {
	nm_dir_t *dir;
	char buffer[2048];
};



void __stdcall nm_dir_traverse_apc_routine(
	void *context,
	IO_STATUS_BLOCK *ioStatusBlock,
	unsigned long reserved)
{
	struct nm_dir_traverse_apc_routine_context *ctx = context;
	LogMessageW(L"In traverse_apc_routine\n");
}



void __stdcall nm_dir_traverse(
	nm_dir_t *dir,
	nm_dir_traverse_callback callback,
	void *param)
{
	unsigned long status;
	IO_STATUS_BLOCK iosb;
	void *eventHandle = 0;

	struct nm_dir_traverse_apc_routine_context ctx;

	ctx.dir = dir;

	PIO_APC_ROUTINE apcRoutine = nm_dir_traverse_apc_routine;
	void *apcContext = &ctx;
	IO_STATUS_BLOCK ioStatusBlock;
	UNICODE_STRING filter = {0};

	UNICODE_STRING objectName;

	//char fileInfoBuffer[8092];
	//FILE_DIRECTORY_INFORMATION *fileInfo = (void*)fileInfoBuffer;

	struct WinDir windir;

	windir.Object.Handle = dir->handle;
	windir.event = 0;


	// allocate memory to hold the directory file info
/*
	void *dataBlock;
	dataBlock = nm_malloc(8092);
	if(!dataBlock)
	{
	}
*/

//	poolAlloc


	//_getDirectoryFiles(dir->handle);

/*
	status = NtQueryDirectoryFile(
		dir->handle,
		eventHandle,
		apcRoutine,
		apcContext,
		&ioStatusBlock,
		ctx.buffer,
		sizeof(ctx.buffer),
		FileDirectoryInformation,
		false,
		0,
		false);
	if(status != STATUS_PENDING)
	{
		// error NtQueryDirectoryFile
		LogMessageW(L"NtQueryDirectoryFile (nm_dir_traverse) failed: 0x%1!x!\n", status);
		return;
	}

	LARGE_INTEGER timeout = {0};
	status = NtWaitForSingleObject(dir->handle, true, 0);
	if(status > 0)
	{
		LogMessageW(L"NtWaitForSingleObject failed: 0x%1!x!\n", status);
		return;
	}
*/

	// if files exists, allocate a nm_file_t structure
	nm_file_t * file = nm_malloc(sizeof(nm_file_t));
	if(!file)
	{
		// error: out of memory
	}


	//objectName.buffer = fileInfo->FileName;

/*
	LogMessageW(L"Filename: %1!.*s! (%2!u!)\n",
		fileInfo->FileNameLength >> 1, fileInfo->FileName,
		fileInfo->FileNameLength >> 1);
*/

//	(char*)fileInfo += fileInfo->NextEntryOffset;


	// will need to stop traversal at some point
	//callback(file, param);


	// free the nm_file_t
	nm_free(file);
}




void __stdcall nm_dir_close(nm_dir_t *dir)
{
	NtClose(dir->handle);
	nm_free(dir);
}


void __stdcall nm_dir_delete(nm_dir_t *dir)
{
	wchar_t *path;
	UNICODE_STRING str;
	OBJECT_ATTRIBUTES oa = {0};

	oa.SizeOf = sizeof(oa);

	//RtlInitUnicodeString(&str, dir->name);
	//RtlInitUnicodeString(&str, path);
	oa.ObjectName = &str;
	NtDeleteFile(&oa);

	nm_dir_close(dir);
}



void __stdcall nm_dir_rename(wchar_t *name)
{
}




void * __stdcall CreateCompilerPipe()
{
	unsigned long status;
	void *fileHandle;
	ACCESS_MASK fileAccess;
	OBJECT_ATTRIBUTES oa = {0};
	IO_STATUS_BLOCK iosb;


	UNICODE_STRING fileName;
	fileName.Buffer = L"clout.txt";
	fileName.Length = 9 << 1;
	fileName.MaximumLength = fileName.Length;

	oa.SizeOf = sizeof(oa);
	oa.ObjectName = &fileName;
	oa.RootDirectory = NtCurrentPeb()->ProcessParameters->CurrentDirectoryHandle;

	fileAccess.mask = FILE_WRITE_DATA;
	status = NtCreateFile(
		&fileHandle,
		fileAccess,
		&oa,
		&iosb,
		0, // AllocationSize
		FILE_ATTRIBUTE_NORMAL, // FileAttributes
		FILE_SHARE_WRITE, // ShareAccess
		FILE_OPEN_IF, // CreateDisposition
		0, // CreateOptions
		0,
		0
	);
	if(status > 0)
	{
		LogMessageA("NtCreateFile failed: 0x%1!x!\n", status);
		return 0;
	}


	LARGE_INTEGER timeout;
	UNICODE_STRING pipeName;
	void *namedPipe;
	ACCESS_MASK pipeAccess;

	pipeName.Buffer = L"\\Device\\NamedPipe\\NomakePipe";
	pipeName.Length = 28 << 1;
	pipeName.MaximumLength = pipeName.Length;

	oa.ObjectName = &pipeName;
	oa.RootDirectory = 0;

	timeout.QuadPart = - (5 * 1000000);

	pipeAccess.mask = SYNCHRONIZE | FILE_READ_DATA;
	status = NtCreateNamedPipeFile(
		&namedPipe,
		pipeAccess,
		&oa, // OBJECT_ATTRIBUTES
		&iosb,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		FILE_CREATE,
		FILE_SYNCHRONOUS_IO_NONALERT, // CreateOptions
		false, // Write in byte mode
		false, // Read in byte mode
		false, // asynchronous io?
		-1, // number of allowed open handles
		1024, // Input buffer size
		1024, // Output buffer size
		&timeout // default timeout
	);
	if(status > 0)
	{
		LogMessageA("NtCreateNamedPipeFile failed: 0x%1!x!\n", status);
		return 0;	
	}

	return namedPipe;
}



void * __stdcall Win32CreateProcess1(UNICODE_STRING *imageName)
{
	void *threadHandle;
	void *fileHandle;
	void *sectionHandle;
	void *processHandle = 0;

	unsigned long status;
	ACCESS_MASK access;
	OBJECT_ATTRIBUTES oa = {0};
	OBJECT_ATTRIBUTES *objectAttrPtr = 0;
	IO_STATUS_BLOCK iosb;
	IO_STATUS_BLOCK *ioStatusBlockPtr = 0;
	unsigned long processFlags;


	void *threadArg = 0;

	oa.SizeOf = sizeof(OBJECT_ATTRIBUTES);
	oa.ObjectName = imageName;
	
	// Open the file
	access.mask = FILE_EXECUTE;
	status = NtCreateFile(
		&fileHandle,
		access,
		&oa,   // OBJECT_ATTRIBUTES *
		&iosb, // IO_STATUS_BLOCK *
		0,     // not creating a new file, no allocation size!!
		0,     // not creating a new file, no attributes!!
		FILE_SHARE_READ, // may not need this
		FILE_OPEN,
		0, // not creating a new file, no create options!!
		0, 0);
	if(status > 0)
	{
		// error: could not find binary file
		LogMessageA("ERROR (0x%1!x!): Could not find process file\n", status);
		return 0;
	}

	// Create a section
	unsigned long sectionAttr = SEC_COMMIT;
	access.mask = SECTION_QUERY | SECTION_MAP_EXECUTE;
	status = NtCreateSection(
		&sectionHandle,
		access,
		0, // OBJECT_ATTRIBUTES
		0, // inherits size from fileHandle
		PAGE_EXECUTE,
		sectionAttr,
		fileHandle);
	if(status > 0)
	{
		LogMessageA("ERROR (0x%1!x!): Could not create section\n", status);
		goto cleanup_file;
	}


	processFlags = PS_INHERIT_HANDLES;
	access.mask = 0;
	status = NtCreateProcessEx(
		&processHandle,
		access,
		0, // OBJECT_ATTRIBUTES
		NtCurrentProcess(),
		processFlags,
		sectionHandle,
		0, // no debug port
		0, // no exception port
		false); // not part of a job object
	if(status > 0)
	{
		LogMessageA("ERROR (0x%1!x!): Could not create process\n", status);
		goto cleanup_section;
	}

	return 1;

	// Create a thread
	threadHandle = Win32CreateThread(processHandle, thread_start_routine, threadArg);
	if(!threadHandle)
	{
		// error: could not create thread
		goto cleanup_process;
	}


cleanup_process:
	NtClose(processHandle);

cleanup_section:
	NtClose(sectionHandle);

cleanup_file:
	NtClose(fileHandle);

	return 0;
}


void * __stdcall Win32CreateProcess2(UNICODE_STRING *imageName)
{

	void *processHandle = 0;
	void *threadHandle = 0;
	ACCESS_MASK processAccess;
	ACCESS_MASK threadAccess;
	unsigned long status;

	PEB *peb = NtCurrentTeb()->ProcessEnvironmentBlock;
	RTL_USER_PROCESS_PARAMETERS *curProcessParams = peb->ProcessParameters;

	RTL_USER_PROCESS_PARAMETERS userParams;
	PS_CREATE_INFO createInfo;
	PS_ATTRIBUTE_LIST attrList;

	OBJECT_ATTRIBUTES poa = {0};
	OBJECT_ATTRIBUTES toa = {0};

	char envData[] = {
	'P',0x0,'A',0x0,'T',0x0,'H',0x0,'=',0x0,'C',0x0,':',0x0,'\\',0x0,
	'P',0x0,'r',0x0,'o',0x0,'g',0x0,'r',0x0,'a',0x0,'m',0x0,' ',0x0,
	'F',0x0,'i',0x0,'l',0x0,'e',0x0,'s',0x0,' ',0x0,'(',0x0,'x',0x0,
	'8',0x0,'6',0x0,')',0x0,'\\',0x0,'M',0x0,'i',0x0,'c',0x0,'r',0x0,
	'o',0x0,'s',0x0,'o',0x0,'f',0x0,'t',0x0,' ',0x0,'V',0x0,'i',0x0,
	's',0x0,'u',0x0,'a',0x0,'l',0x0,' ',0x0,'S',0x0,'t',0x0,'u',0x0,
	'd',0x0,'i',0x0,'o',0x0,' ',0x0,'1',0x0,'4',0x0,'.',0x0,'0',0x0,
	'\\',0x0,'V',0x0,'C',0x0,'\\',0x0,'b',0x0,'i',0x0,'n',0x0,0x0,0x0,
	0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
	};


	LogMessageW(L"Environment: %1!.*s!\n", sizeof(envData) >> 1, (wchar_t*)envData);

	poa.SizeOf = sizeof(OBJECT_ATTRIBUTES);
	//poa.ObjectName = filePath;

	toa.SizeOf = sizeof(OBJECT_ATTRIBUTES);
	
	processAccess.mask = 0x02000000L;
	threadAccess.mask = 0x02000000L;

	RtlZeroMemory(&userParams, sizeof(userParams));
	RtlZeroMemory(&createInfo, sizeof(createInfo));
	RtlZeroMemory(&attrList, sizeof(attrList));

	userParams.MaximumLength = sizeof(RTL_USER_PROCESS_PARAMETERS);
	userParams.Length = sizeof(RTL_USER_PROCESS_PARAMETERS);
	createInfo.Size = sizeof(createInfo);
	attrList.TotalLength = sizeof(attrList);


	OBJECT_ATTRIBUTES objAttr = {0};
	IO_STATUS_BLOCK iosb;

	void *fileHandle;

	fileHandle = CreateCompilerPipe();


	userParams.CommandLine.Buffer = imageName->Buffer;
	userParams.CommandLine.Length = imageName->Length;
	userParams.CommandLine.MaximumLength = imageName->Length;

	userParams.Environment = (wchar_t*)envData;
	userParams.EnvironmentSize = sizeof(envData);
	userParams.EnvironmentVersion = 0;
	userParams.Flags = RTL_USER_PROCESS_PARAMETERS_NORMALIZED;
	userParams.StdOutputHandle = fileHandle; //curProcessParams->StdOutputHandle; // set to file handle
	userParams.StdErrorHandle = fileHandle; //curProcessParams->StdOutputHandle; // set to file handle

	/*
	LogMessageA("MaximumLength: %1!u!, %2!u!\n",
		curProcessParams->MaximumLength, userParams.MaximumLength);
	LogMessageA("Length: %1!u!, %2!u!\n",
		curProcessParams->Length, userParams.Length);
	*/

	LogMessageA("ImageSubsystem: 0x%1!x!\n", peb->ImageSubsystem);
	LogMessageA("ImageSubsystemMajorVersion: 0x%1!x!\n", peb->ImageSubsystemMajorVersion);
	LogMessageA("ImageSubsysteMinorVersion: 0x%1!x!\n", peb->ImageSubsystemMinorVersion);


	LogMessageA("ConsoleHandle: 0x%1!p!\n", curProcessParams->ConsoleHandle);
	LogMessageA("StdInputHandle: 0x%1!p!\n", curProcessParams->StdInputHandle);
	LogMessageA("StdOutputHandle: 0x%1!p!\n", curProcessParams->StdOutputHandle);
	LogMessageA("StdErrorHandle: 0x%1!p!\n", curProcessParams->StdErrorHandle);


	attrList.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	attrList.Attributes[0].Size = imageName->Length;
	attrList.Attributes[0].Value = imageName->Buffer;


	/*
	PS_STD_HANDLE_INFO handleInfo = {0};
	handleInfo.Flags = (0x7 << 3) | PsNeverDuplicate; // duplicate all standard handles
	handleInfo.StdHandleSubsystemType = 0x3;

	attrList.Attributes[1].Attribute = PS_ATTRIBUTE_STD_HANDLE_INFO;
	attrList.Attributes[1].Size = sizeof(PS_STD_HANDLE_INFO);
	attrList.Attributes[1].ValuePtr = &handleInfo;
	*/

	unsigned long processFlags =
	PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT |
	PROCESS_CREATE_FLAGS_INHERIT_HANDLES;


	// need to pipe the compiler output
	status = NtCreateUserProcess(
		&processHandle,
		&threadHandle,
		processAccess,
		threadAccess,
		0, // Process OBJECT_ATTRIBUTES
		&toa, // Thread OBJECT_ATTRIBUTES
		processFlags, // Process flags
		0, // thread flags
		&userParams, // process params
		&createInfo, // create info
		&attrList // attribute list
	);
	if(status > 0)
	{
		LogMessageA("ERROR (0x%1!x!): Could not create process\n", status);
		return 0;
	}


	status = NtWaitForSingleObject(threadHandle, false, 0);
	if(status > 0)
	{
		LogMessageA("NtWaitForSingleObject(win32CreateProcess) failed: %1!x!\n", status);	
		return 0;
	}

	/*
	LARGE_INTEGER timeout;
	timeout.QuadPart = -(2000 * 10000);
	NtDelayExecution(true, &timeout);
	*/

	return 0;
}


void __stdcall ProcessApcRoutine(void *param, IO_STATUS_BLOCK *iosb, unsigned long r)
{
	LogMessageA("ProcessApcRoutine\n");
}


void * __stdcall Win32CreateProcess3(UNICODE_STRING *imageName)
{

	SECURITY_ATTRIBUTES processSA;
	SECURITY_ATTRIBUTES threadSA;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	bool success;


	void *fileHandle = CreateCompilerPipe();

	LogMessageA("FileHandle: %1!u!\n", fileHandle);

	RtlZeroMemory(&si, sizeof(si));
	si.SizeOf = sizeof(si);

	si.Flags = STARTF_USESTDHANDLES;
	si.StdInput  = 0;
	si.StdOutput = fileHandle;
	si.StdError  = fileHandle;

	LogMessageA("FileHandle: 0x%1!x1\n", fileHandle);

	imageName->Buffer =
	L"C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\bin\\cl.exe";
	imageName->Length = 65 << 1;

	success = CreateProcessW(
		0,
		imageName->Buffer,
		0, 0,
		true,
		CREATE_NO_WINDOW, // creation flags
		0, // environment block
		0, // current directory
		&si,
		&pi
	);
	if(!success){
		LogMessageA("CreateProcessW failed: 0x%1!u!\n", GetLastError());	
		return 0;
	}

	LARGE_INTEGER timeout;
	unsigned long status;
	char ReadBuffer[1024];
	IO_STATUS_BLOCK iosb;
	RtlZeroMemory(ReadBuffer, 1024);

	timeout.QuadPart = -(5 * 10000000);



	status = WaitForSingleObject(pi.ProcessHandle, 2000);
	if(status != 0)
	{
		//LogMessageA("Wait for pipe failed: 0x%1!x1\n", status);
		LogMessageA("Wait for pipe failed: 0x%1!x1\n", GetLastError());
		return 0;
	}

	//NtDelayExecution(true, &timeout);

	status = NtReadFile(fileHandle, 0, 0, 0, &iosb, ReadBuffer, 1024, 0, 0);
	//LogMessageA("Buffer: %.*s\n", 
	if(status > 0)
	{
		LogMessageA("NtReadFile failed: 0x%1!x!\n", status);	
		return 0;
	}

	LogMessageA("Buffer: %1!.*s!\n", 128, ReadBuffer);


	//NtClose(fileHandle);

	return 0;
}

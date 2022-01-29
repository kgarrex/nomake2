
typedef struct WinSystem
{
	void *processHandle;
} WinSystem;



void * __stdcall _alloc(size_t size)
{
	unsigned long status;
	void *baseAddress = 0;

	status = NtAllocateVirtualMemory(
		NtCurrentProcess(),
		&baseAddress,
		0, &size, MEM_COMMIT, PAGE_READWRITE);
	if(status > 0){
		LogMessageW(L"NtAllocateVirtualMemory failed: %1!x!\n", status);
		return 0;
	}
	return baseAddress;
}


unsigned long __stdcall threadRoutine(void *param)
{
	TEB * teb = NtCurrentTeb();

	LogMessageA("ProcessId: 0x%1!x!   |    ThreadId: 0x%2!x!\n",
		teb->ProcessId, teb->ThreadId);

	return 0;
}


struct WinThreadPool
{
	unsigned int threadCount;
	void  * threadArray[32];
};


void __stdcall createThreadPool(void *processHandle, struct WinThreadPool *pool)
{
	unsigned long status;
	void *threadHandle;
	ACCESS_MASK access;
	OBJECT_ATTRIBUTES objectAttr = {0};
	unsigned int i;

	unsigned int threadCount = pool->threadCount;

	access.mask = THREAD_ALERT | THREAD_SUSPEND_RESUME;

	// create 

	for(i = 0; i < threadCount; ++i)
	{
		threadHandle = Win32CreateThread(processHandle, threadRoutine, 0);

/*
		status = NtCreateThreadEx(
			&threadHandle,
			access,
			0,
			processHandle,
			threadRoutine,
			0,
			0,
			0, 0, 0,
			0);

		if(status > 0)
		{
			LogMessageA("NtCreateThreadEx failed: 0x%1!x!\n", status);
			return;
		}
*/

		pool->threadArray[i] = threadHandle;
	}
}


#define offsetof(type, member) ((unsigned int)(&(((type*)(0))->member)))

TEB * __stdcall NtCurrentTeb2(void);


void __stdcall getSyscallTable()
{

	TEB *teb = NtCurrentTeb();
	PEB *peb = teb->ProcessEnvironmentBlock;

	LogMessageA("\nOS Version: %1!u!.%2!u!\n",
		peb->OSMajorVersion, 
		peb->OSMinorVersion);

	LogMessageA("OS Build Number: %1!u!\n", peb->OSBuildNumber);

/*
	switch(peb->OSBuildNumber)
	{
	case: 19042	
		
	}
*/
}


void __stdcall openSystem(struct WinSystem *System)
{
	unsigned long status;
	void *processHandle;
	unsigned long returnLength;


	TEB *teb = NtCurrentTeb();
	PEB *peb = teb->ProcessEnvironmentBlock;


	getSyscallTable();


	/*
	LogMessageW(L"Diff: %1!u!\n", 0x714 - 0x700);
	LogMessageW(L"Diff: %1!u!\n", 0x890 - 0x878);
	LogMessageW(L"Sizeof(UNICODE_STRING): 0x%1!u!\n", sizeof(UNICODE_STRING));

	
	LogMessageW(L"Process Handle: 0x%1!p!\n", teb->ProcessId);
	LogMessageW(L"Real Process Handle: 0x%1!p!\n", teb->RealProcessId);
	LogMessageW(L"Thread Handle: 0x%1!p!\n", teb->ThreadId);
	LogMessageW(L"Real Thread Handle: 0x%1!p!\n", teb->RealThreadId);
	LogMessageW(L"Gdi Cached Process Handle: 0x%1!p!\n", teb->GdiCachedProcessHandle);
	LogMessageW(L"Gdi Client Pid: 0x%1!p!\n", teb->GdiClientPid);
	LogMessageW(L"Gdi Client Tid: 0x%1!p!\n", teb->GdiClientTid);

	LogMessageW(L"OFFSET FpSoftwareStatusRegister: 0x%1!x!\n", offsetof(TEB, FpSoftwareStatusRegister));
	LogMessageW(L"OFFSET ExcpetionCode: 0x%1!x!\n", offsetof(TEB, ExceptionCode));
	LogMessageW(L"OFFSET RealProcessId: 0x%1!x!\n", offsetof(TEB, RealProcessId));
	LogMessageW(L"OFFSET GdiClientTid: 0x%1!x!\n", offsetof(TEB, GdiClientTid));
	LogMessageW(L"OFFSET UserReserved: 0x%1!x!\n", offsetof(TEB, UserReserved));
	LogMessageW(L"OFFSET DeallocationStack: 0x%1!x!\n", offsetof(TEB, DeallocationStack));
	LogMessageW(L"OFFSET FlsSlots: 0x%1!x!\n", offsetof(TEB, FlsSlots));
	*/



	ACCESS_MASK access;
	OBJECT_ATTRIBUTES oa = {0};
	CLIENT_ID clientId = {0};

	oa.SizeOf = sizeof(OBJECT_ATTRIBUTES);


	PROCESS_DEVICEMAP_INFORMATION deviceMap;

	status = NtQueryInformationProcess(
		NtCurrentProcess(),
		ProcessDeviceMap,
		&deviceMap,
		sizeof(deviceMap),
		&returnLength
	);
	if(status > 0)
	{
		LogMessageW(L"NtQueryInformationProcess failed: 0x%1!x!\n", status);
		return;
	}
	
	LogMessageA("DriveType: %1!s!\n", deviceMap.Query.DriveType);

	RTL_USER_PROCESS_PARAMETERS *upp = peb->ProcessParameters;

	LogMessageW(L"CurrentDirectoryLength: %1!u!\n", upp->CurrentDirectoryPath.Length);
	LogMessageW(L"CurrentDirectory: %1!s!\n", upp->CurrentDirectoryPath.Buffer);

	LogMessageW(L"ImageFileNameLength: %1!u!\n", upp->ImagePathName.Length);
	LogMessageW(L"ImageFileName: %1!s!\n", upp->ImagePathName.Buffer);

	LogMessageW(L"CommandLineLength: %1!u!\n", upp->CommandLine.Length);
	LogMessageW(L"CommandLine: %1!s!\n", upp->CommandLine.Buffer);

	LogMessageW(L"EnvironmentSize: %1!u!\n", upp->EnvironmentSize);
	LogMessageW(L"Environment: %1!.*s!\n", upp->EnvironmentSize, upp->Environment);


	struct WinThreadPool Pool;

	Pool.threadCount = teb->ProcessEnvironmentBlock->NumberOfProcessors;
	createThreadPool(NtCurrentProcess(), &Pool);

	LARGE_INTEGER timeout = {0, 3000};
	status = NtDelayExecution(false, &timeout);
	if(status > 0)
	{
		LogMessageA("NtDelayExecution failed: 0x%1!x!\n", status);
		return;
	}
}


void Win32CreateProcess(UNICODE_STRING *filepath)
{
	unsigned long status;
	void *fileHandle;
	ACCESS_MASK access;
	OBJECT_ATTRIBUTES oa = {0};
	IO_STATUS_BLOCK ioStatusBlock;

	access.mask = 0;

	oa.SizeOf = sizeof(oa);
	oa.ObjectName = filepath;

	// open file
	status = NtOpenFile(&fileHandle, access, &oa,
		&ioStatusBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE);
	if(status > 0)
	{
		LogMessageA("NtOpenFile failed: 0x%1!x!\n", status);
		return;
	}

	// create section and map file

	//status = NtCreateSectionEx(&sectionHandle);
	// create thread
	// create process
}

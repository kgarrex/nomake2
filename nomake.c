
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
	#define NOMAKE_WINDOWS
	#if defined(_WIN64)
		#define NOMAKE_64BIT
	#else
		#define NOMAKE_32BIT
	#endif

#elif defined(__APPLE__)
	#if TARGET_OS_IPHONE
		#define NOMAKE_IPHONE
	#elif TARGET_OS_MAC
		#define NOMAKE_MAC_OS
	#endif
#elif defined(__unix__)
	#define NOMAKE_UNIX
#elif defined(__linux__)
	#define NOMAKE_LINUX
	//#elif defined(__x86_64__)
#elif defined(__ANDROID__)
	#define NOMAKE_ANDROID
#endif




#if defined(__x86_64__)
	#define NOMAKE_64BIT
#endif


#define INCLUDE_KERNEL32 



//#include "jsmn.h"


#include "nomake.h"



typedef unsigned char * nm_utf8_t;


/*
void *nm_utf8_encode(utf8_t * utf8, long c)
{
	unsigned char *s = utf8->buffer;

	if (c >= (1L << 16)){
	//if(c & 0xff000000){
		s[0] = 0xf0 |  (c >> 18);
		s[1] = 0x80 | ((c >> 12) & 0x3f);
		s[2] = 0x80 | ((c >>  6) & 0x3f);
		s[3] = 0x80 | ((c >>  0) & 0x3f);
		return s + 4;
	}
	else if(c >= (1L << 11)){
	//else if(c & 0xffff0000){
		s[0] = 0xe0 |  (c >> 12);
		s[1] = 0x80 | ((c >>  6) & 0x3f);
		s[2] = 0x80 | ((c >>  0) & 0x3f);
		return s + 3;
	}
	else if (c >= (1L << 7)) {
	//else if(c & 0xffffff00){
		s[0] = 0xc0 |  (c >>  6);
		s[1] = 0x80 | ((c >>  0) & 0x3f);
		return s + 2;
	}
	else {
		s[0] = c;
		return s + 1;
	}
}
*/



/*
 * Decode the next character, C, from BUF, reporting errors in E.
 *
 * Since this is a branchless decoder, four bytes will be read from the
 * buffer regardless of the actual length of the next character. This
 * means the buffer _must_ have at least three bytes of zero padding
 * following the end of the data stream.
 *
 * Errors are reported in E, which will be non-zero if the parsed
 * character was somehow invalid: invalid byte sequence, non-canonical
 * encoding, or a surrogate half.
 *
 * The function returns a pointer to the next character. When an error
 * occurs, this pointer will be a guess that depends on the particular
 * error, but it will always advance at least one byte.
 *
 * The function is used only when JszlEncode_Utf8Fast is set as the encoding.
 * fast utf8 decoding can only be guaranteed from a stream encoded with at least
 * three bytes of zero padding at the end.
 */
void * __cdecl nm_utf8_decode_char_fast(void *buf, uint32_t *c, int *e)
{
    static const char lengths[] = {
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 3, 3, 4, 0
    };
    static const int masks[]     = {0x00, 0x7f, 0x1f, 0x0f, 0x07};
    static const uint32_t mins[] = {4194304, 0, 128, 2048, 65536};
    static const int shiftc[]    = {0, 18, 12, 6, 0};
    static const int shifte[]    = {0, 6, 4, 2, 0};

    unsigned char *s = buf;
    int len = lengths[s[0] >> 3];

    /* Compute the pointer to the next character early so that the next
     * iteration can start working on the next character. Neither Clang
     * nor GCC figure out this reordering on their own.
     */
    unsigned char *next = s + len + !len;

    /* Assume a four-byte character and load four bytes. Unused bits are
     * shifted out.
     */
    *c  = (uint32_t)(s[0] & masks[len]) << 18;
    *c |= (uint32_t)(s[1] & 0x3f) << 12;
    *c |= (uint32_t)(s[2] & 0x3f) <<  6;
    *c |= (uint32_t)(s[3] & 0x3f) <<  0;
    *c >>= shiftc[len];

    /* Accumulate the various error conditions. */
    *e  = (*c < mins[len]) << 6; // non-canonical encoding
    *e |= ((*c >> 11) == 0x1b) << 7;  // surrogate half?
    *e |= (*c > 0x10FFFF) << 8;  // out of range?
    *e |= (s[1] & 0xc0) >> 2;
    *e |= (s[2] & 0xc0) >> 4;
    *e |= (s[3]       ) >> 6;
    *e ^= 0x2a; // top two bits of each tail byte correct?
    *e >>= shifte[len];

    return next;
}


typedef struct nm_symbol_batch {
	const char *name;
} nm_symbol_batch;



#define WINNT_STATUS_PENDING 0x103

// TODO USE TEMPORARY PRINT FUNCTION TO TEST THIS API OUT

/**
 * \Device\ConDrv\Connect
 * \Device\ConDrv\Input
 * \Device\ConDrv\Output
 * "CON"     | \Device\ConDrv\Console
 * "CONIN$"  | \Device\ConDrv\CurrentIn
 * "CONOUT$" | \Device\ConDrv\CurrentOut
*/
void __stdcall nm_tty_out(char *out, unsigned long length)
{
#if defined(NOMAKE_WINDOWS)
	unsigned long status;
	void *console;

	ACCESS_MASK access;
	IO_STATUS_BLOCK iosb = {0};
	OBJECT_ATTRIBUTES oa = {0};
	UNICODE_STRING path;
	LARGE_INTEGER offset = {0};

	//RtlInitUnicodeString(&path, L"\\Device\\ConDrv\\Console");
	//RtlInitUnicodeString(&path, L"\\Device\\ConDrv\\CurrentOut");
	RtlInitUnicodeString(&path, L"\\Device\\ConDrv\\Output");
	oa.SizeOf = sizeof(oa);
	//oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.ObjectName = &path;
	
	//THIS SHOULD SPECIFY WRITE PERMISSIONS
	//access.mask = STANDARD_RIGHTS_REQUIRED | FILE_WRITE_DATA; 
	access.mask =
		SYNCHRONIZE
		//|FILE_READ_DATA
		|FILE_WRITE_DATA
		//|FILE_APPEND_DATA
		//|FILE_WRITE_ATTRIBUTES
		; 

	// open the standard output handle (default is console)
	status = NtOpenFile(&console, access, &oa, &iosb, 0, 0);
	if(status > 0){
		LogMessageW(L"NtOpenFile failed: 0x%1!x!\n", status);
		return;
	}


	// write to the standard output handle
	status = NtWriteFile(console, 0, 0, 0, &iosb, out, length, &offset, 0);
	if(status > 0){
		if(status != WINNT_STATUS_PENDING){
			LogMessageW(L"NtWriteFile failed: 0x%1!x!\n", status);
			return;
		}
		else {
			// sleep?
		}
	}

	// close the handle
	NtClose(console);
#endif
}


void __stdcall nm_tty_in();


#define WINNT_STATUS_OBJECT_TYPE_MISMATCH 0xc0000024


void win32_file()
{
	unsigned long status;

//	RtlInitUnicodeString(&str, 
}



/*
void * __stdcall nm_pool_getBlock()
{

}
*/

void __stdcall nm_get_system_info(nm_app_t *app)
{
	SYSTEM_BASIC_INFORMATION sysInfo;
	unsigned long status;
	unsigned long returnLength;

// Get processor info
	status = NtQuerySystemInformation(
		SystemBasicInformation,
		&sysInfo,
		sizeof(SYSTEM_BASIC_INFORMATION),
		&returnLength);
	if(status > 0)
	{
		LogMessageW(L"NtQuerySystemInformation failed 0x%1!x!\n", status);
		return;
	}

/*
	LogMessageW(L"Reserved: %1!u!\n", sysInfo.Reserved);
	LogMessageW(L"Processor Count: %1!u!\n", sysInfo.NumberOfProcessors);
	LogMessageW(L"Page Size: %1!u!\n", sysInfo.PageSize);
	LogMessageW(L"Timer Resolution: %1!u!\n", sysInfo.TimerResolution);
	LogMessageW(L"Physical Page Count: %1!u!\n", sysInfo.NumberOfPhysicalPages);
	LogMessageW(L"Allocation Granularity: %1!u!\n",
		sysInfo.AllocationGranularity);
	LogMessageW(L"User Mode Address: 0x%1!x! - 0x%2!x!\n",
		sysInfo.MinimumUserModeAddress, sysInfo.MaximumUserModeAddress);
*/
}


#define Is64Bit() (sizeof(void*) == 8)
#define Is32Bit() (sizeof(void*) == 4)


int (__cdecl *sprintf)(char *buf, char *format, ...);

int (__cdecl *snprintf)(char *buffer, size_t count, char *format, ...);


nm_app_t * __stdcall nm_init()
{
	unsigned long status;
	void *ioCompletionHandle1 = 0;
	void *ioCompletionHandle2 = 0;
	ACCESS_MASK access;
	OBJECT_ATTRIBUTES oa = {0};
	void *module;

	UNICODE_STRING dllName;
	ANSI_STRING procName;


	dllName.length = 18;
	dllName.maximum_length = 18; 
	dllName.buffer = L"ntdll.dll"; 

	status = LdrLoadDll(
		L"\\??\\C:\\Windows\\System32",
		0, &dllName, &module);
	if(status > 0)
	{
		LogMessageW(L"LdrLoadDll failed: 0x%1!x!\n", status);
		return 0;
	}

	procName.length = 9;
	procName.maximum_length = 9;
	procName.buffer = "_snprintf";

	status = LdrGetProcedureAddress(module, &procName, 0, (void**)&snprintf);
	if(status > 0)
	{
		LogMessageW(L"LdrGetProcedureAddress failed: 0x%1!x!\n", status);
		return 0;
	}


// Initialize the memory pool here



// Get the system info
	nm_get_system_info(0);


// Create an io completion port 
	access.mask = SYNCHRONIZE
	//| IO_COMPLETION_QUERY_STATE
	//| IO_COMPLETION_MODIFY_STATE
	;


	//LogMessageW(
	LogMessageA("HERE\n");

	// can create multiple io completion ports
	status = NtCreateIoCompletion(&ioCompletionHandle1, access, 0, 0);
	if(status > 0)
	{
		// error: could not create io completion port 1
	}

	status = NtCreateIoCompletion(&ioCompletionHandle2, access, 0, 0);
	if(status > 0)
	{
		// error: could not create io completion port 2
	}


	LogMessageA("ioCompletionHandle1: 0x%1!x!\n", ioCompletionHandle1);
	LogMessageA("ioCompletionHandle2: 0x%1!x!\n", ioCompletionHandle2);


	return 0;
}



void __stdcall nm_timer_apc_routine(
	void *timerContext,
	unsigned long timerLowValue,
	long timerHighValue)
{
	//LogMessageW(L"In nm_timer_apc_routine\n");
	nm_printf("In nm_timer_apc_routine: %u\n", 34);
}



nm_timer_t * __stdcall nm_timer_new(nm_app_t *app)
{
	unsigned long status;
	void *timerHandle;
	ACCESS_MASK access;
	OBJECT_ATTRIBUTES oa = {0};
	TIMER_SET_COALESCABLE_TIMER_INFO timerInfo = {0};

	access.mask = SYNCHRONIZE
	| TIMER_MODIFY_STATE
//	| TIMER_QUERY_STATE
//	| STANDARD_RIGHTS_ALL
	;

	status = NtCreateTimer(&timerHandle, access, 0, SynchronizationTimer);
	if(status > 0)
	{
		LogMessageW(L"NtCreateTimer failed: 0x%1!x!\n", status);
		return 0;
	}

	COUNTED_REASON_CONTEXT crc = {0};

	timerInfo.DueTime.QuadPart = 0;
	timerInfo.TimerApcRoutine = nm_timer_apc_routine;
	timerInfo.TimerContext = 0;
	timerInfo.WakeContext = 0;
	timerInfo.Period =  2 * 10; // 100ms units
	timerInfo.TolerableDelay = 0;
	timerInfo.PreviousState = 0;
	
	status = NtSetTimerEx(
		timerHandle,
		TimerSetCoalescableTimer,
		&timerInfo,
		sizeof(timerInfo));
	if(status > 0)
	{
		LogMessageW(L"NtSetTimerEx failed: 0x%1!x!\n", status);
		return 0;
	}

	status = NtWaitForSingleObject(timerHandle, true, 0);

	//NtClose(timerHandle);

	return 0;
}


void __stdcall nm_timer_delete(nm_timer_t *timer)
{

}


unsigned long __stdcall thread_start_routine(void *arg)
{
	LogMessageW(L"In thread_start_routine\n");
	return 0;
}


/*
void __stdcall SetDefaultContext(CONTEXT *Context)
{

// IFDEF _x86
	Context->x86.SegGs = USER_DS;
	Context->x86.SegFs = TEB_SELECTOR;
	Context->x86.SegEs = USER_DS;
	Context->x86.SegDs = USER_DS;
	Context->x86.SegCs = USER_CS;
	Context->x86.SegSs = USER_DS;

	Context->x86.Eip = (DWORD)entry;
	Context->x86.Esp = (DWORD)initialTeb.FixedStack.Base;
	Context->x86.Esp -= sizeof(void*);
	Context->x86.Esp = (DWORD)arg;

// ELSE IFDEF _64
	Context->x86.SegGs = TEB_SELECTOR;

// ENDIF

}
*/


void *__stdcall Win32CreateThreadStack(size_t stackSize)
{
	unsigned long status;
	void *processHandle;
	void *baseAddress = 0;


	// allocate stack reserve stack space here

	status = NtAllocateVirtualMemory(
		NtCurrentProcess(),
		&baseAddress,
		0, // no zero bits
		&stackSize,
		MEM_RESERVE|MEM_COMMIT,
		PAGE_EXECUTE_READWRITE); //PAGE_EXECUTE_READWRITE);

	if(status > 0){
		LogMessageA("NtAllocateVirtualMemory failed: 0x%1!x!\n", status);
		return 0;
	}

	return baseAddress;
}



void *__stdcall Win32CreateThreadPoolStack()
{
	TEB *Teb;
	unsigned long status;
	void *reservedBaseAddress;
	void *baseAddress;
	void *stackLimitAddress;
	void *guardPage;
	unsigned int numThreads;
	INITIAL_TEB *initteb;

	//INITIAL_TEB *

	unsigned long oldProtect;
	size_t reservedStackSize = 0x10000;
	size_t pageSize = 0x1000;
	unsigned long stackSize = pageSize * 4;

	Teb = NtCurrentTeb();

	void *processHandle = NtCurrentProcess();
	numThreads = Teb->ProcessEnvironmentBlock->NumberOfProcessors;


	// Reserve the full stack space for the pool
	status = NtAllocateVirtualMemory(
		processHandle,
		&reservedBaseAddress,
		0,
		&reservedStackSize,
		MEM_RESERVE,
		PAGE_READWRITE);
	if(status > 0)
	{
		LogMessageA("NtAllocateVirtualMemory failed: 0x%1!x!\n", status);
		return 0;
	}


	//numThreads & 0x3;
	
	baseAddress = 0;
	stackLimitAddress = (char*)reservedBaseAddress + reservedStackSize;

	for(int i = numThreads; i--; )
	{

// commit the stack limit address of each thread stack
		status = NtAllocateVirtualMemory(
			processHandle,
			&stackLimitAddress, 
			0,
			&stackSize, // total size of a stack
			MEM_COMMIT,
			PAGE_READWRITE);
		if(status > 0)
		{
			LogMessageA("NtAllocateVirtualMemory failed: 0x%1!x!\n", status);	
			return 0;
		}

		initteb = baseAddress;

		guardPage = (char*)baseAddress + (stackSize - pageSize);

// protect the limit address of each thread which is the last page of the stack
		status = NtProtectVirtualMemory(
			processHandle,
			&guardPage,  
			&pageSize, // size of 1 page
			PAGE_READWRITE | PAGE_GUARD,
			&oldProtect);
		if(status > 0)
		{
			LogMessageA("NtProtectVirtualMemory failed: 0x%1!x!\n", status);	
			return 0;
		}

		(char*)baseAddress += stackSize;
	}
	
	return 0;
}


void __stdcall Win32DestroyUserStack(void *userStack)
{
	//NtFreeVirtualMemory(NtCurrentProcess(), &userStack, );
}



#define _NTCREATETHREADEX


void * __stdcall Win32CreateThread(
	void *processHandle, PUSER_THREAD_START_ROUTINE entry, void *arg)
{
	OBJECT_ATTRIBUTES oa = {0};
	ACCESS_MASK access = {0};
	unsigned long status;
	void *threadHandle  = 0;

	void *stackBottom;
	size_t stackSize = 0x1000;


	processHandle = processHandle ? processHandle : NtCurrentProcess(); 

	//access.mask = THREAD_ALERT | THREAD_SUSPEND_RESUME | STANDARD_RIGHTS_ALL;

	access.mask = STANDARD_RIGHTS_ALL | SYNCHRONIZE |
		THREAD_TERMINATE | THREAD_SET_CONTEXT | THREAD_IMPERSONATE |
		THREAD_SET_INFORMATION | THREAD_ALERT |
		THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME |
		THREAD_QUERY_INFORMATION | THREAD_DIRECT_IMPERSONATION
		;


	// allocate user stack space here
	stackBottom = Win32CreateThreadStack(stackSize);
	
	oa.SizeOf = sizeof(oa);
		
	CLIENT_ID clientId = {0};
	CONTEXT threadContext;
	INITIAL_TEB initialTeb = {0};

	threadContext.x86.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER |
		CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS |
		CONTEXT_EXTENDED_REGISTERS
		;

	status = NtGetContextThread(NtCurrentThread(), &threadContext);
	if(status > 0)
	{
		LogMessageA("NtGetContextThread failed: 0x%1!x!\n", status);
		return 0;
	}

	initialTeb.FixedStack.Base = (char*)stackBottom + stackSize;
	initialTeb.FixedStack.Limit = stackBottom;

	threadContext.x86.SegGs = 0; //USER_DS;
	threadContext.x86.SegFs = TEB_SELECTOR;
	threadContext.x86.SegEs = USER_DS;
	threadContext.x86.SegDs = USER_DS;
	threadContext.x86.SegCs = USER_CS;
	threadContext.x86.SegSs = USER_DS;

	threadContext.x86.Eip = (DWORD)entry;
	threadContext.x86.Esp = (DWORD)initialTeb.FixedStack.Base;
	threadContext.x86.Esp -= sizeof(void*);
	threadContext.x86.Esp = (DWORD)arg;


#ifdef _NTCREATETHREADEX
	status = NtCreateThreadEx(
		&threadHandle,
		access,
		&oa,
		processHandle,
		entry,
		0, // Argument
		0, // CreateFlags
		0, // ZeroBits
		0, // CommitSize
		0, // ReserveSize
		0);
#else
	status = NtCreateThread(
		&threadHandle,
		access,
		&oa, //&oa,
		processHandle,
		&clientId,
		&threadContext,
		&initialTeb,
		false);
#endif
	if(status > 0)
	{
		// error: could not create thread
		LogMessageA("NtCreateThread failed: 0x%1!x!\n", status);
		return 0;
	}

	LogMessageA("THREAD CREATED!\n");

	return threadHandle;
}


void * __stdcall win32CreateProcess(void *dirHandle, char *name, size_t length)
{
	unsigned long status;
	ACCESS_MASK access;
	OBJECT_ATTRIBUTES oa = {0};
	OBJECT_ATTRIBUTES *objectAttrPtr = 0;
	IO_STATUS_BLOCK iosb;
	IO_STATUS_BLOCK *ioStatusBlockPtr = 0;
	unsigned long processFlags;
	void *debugPort     = 0;
	void *exceptionPort = 0;

	void *fileHandle    = 0;
	void *sectionHandle = 0;
	void *processHandle = 0;
	void *threadHandle  = 0;

	void *threadArg = 0;

	oa.SizeOf = sizeof(OBJECT_ATTRIBUTES);
	processFlags = PS_INHERIT_HANDLES;

	
	// Open the file
	access.mask = 0;
	status = NtCreateFile(
		&fileHandle,
		access,
		objectAttrPtr,
		ioStatusBlockPtr,
		0, // not creating a new file, no allocation size!!
		0, // not creating a new file, no attributes!!
		FILE_SHARE_READ, // may not need this
		FILE_OPEN,
		0, // not creating a new file, no creat options
		0, 0);
	if(status > 0)
	{
		// error: could not find binary file
	}

	// Create a section
	unsigned long sectionAttr = SEC_COMMIT;
	access.mask = 0;
	status = NtCreateSection(
		&sectionHandle,
		access,
		objectAttrPtr,
		0, // inherits size from fileHandle
		PAGE_EXECUTE,
		sectionAttr,
		fileHandle);
	if(status > 0)
	{
		// error: could not create section
		goto cleanup_file;
	}

	access.mask = 0;
	status = NtCreateProcessEx(
		&processHandle,
		access,
		objectAttrPtr,
		NtCurrentProcess(),
		processFlags,
		sectionHandle,
		debugPort,
		exceptionPort,
		false);
	if(status > 0)
	{
		// error: could not create process
		goto cleanup_section;
	}

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


/**
 * Create a child process that can then be manipulated with all nm_process_x
 * api calls
*/
nm_process_t * __stdcall nm_process(nm_process_t *parent, nm_file_t *file) 
{
	//file->dir
	//win32CreateProcess();
	return 0;
}


void __stdcall nm_process_run(nm_process_t *process);


void __stdcall nm_processs_destroy(nm_process_t *process);


void nm_pool_putBlock()
{

}


int __cdecl nm_printf(char *format, ...)
{
	int count = 0;
	va_list args;
	char buf[256];

	va_start(args, format);
	count = snprintf(buf, 256, format, *args);
	//count = sprintf(buf, format, *args);
	va_end(args);

	nm_tty_out(buf, count);

	return count;
}


void * __stdcall nm_malloc(size_t size)
{
	unsigned long status;
	void *base_address = 0;

	status = NtAllocateVirtualMemory(
		NtCurrentProcess(),
		&base_address,
		0, &size, MEM_COMMIT, PAGE_READWRITE);
	if(status > 0){
		LogMessageW(L"NtAllocateVirtualMemory failed: %1!x!\n", status);
		return 0;
	}

	return base_address;
}


void __stdcall nm_free(void *ptr)
{
	unsigned long status;
	size_t size = 0; // this should be gathered from chunk

	status = NtFreeVirtualMemory(
		NtCurrentProcess(), &ptr, &size, MEM_RELEASE); 

	return;
}



void * __stdcall nm_memcpy(void *dest, void *src, size_t len)
{
	//memcpy(dest, src, len);
	while(len--)
	{
		*((char*)dest)++ = *((char*)src)++;
	}
	return dest;
}



nm_str_t * __stdcall nm_str_new(char *utf8, size_t size)
{
	nm_str_t *str = 0;

	// allocate the string structure here
	str = nm_malloc( sizeof(nm_str_t) );
	if(!str)
	{
		LogMessageW(L"Failed to allocate str\n");
		return 0;
	}

	// allocate the string buffer here
	str->buffer = nm_malloc(size);
	if(!str->buffer)
	{
		LogMessageW(L"Failed to allocate string buffer\n");
		return 0;
	}

	// copy the utf8 string into the buffer

	return str;
}



void win32_char_to_unicode(UNICODE_STRING *us,
	char *str, uint32_t len, wchar_t buf[], size_t size)
{
	unsigned short n;
	n = str8to16(buf, str, len);
	us->length = n;
	us->maximum_length = size;
	us->buffer = buf;
}


//void nm_core_load_library(nm_utf8_t FilePath)
nm_lib_t * __stdcall nm_lib_load(wchar_t *filePath)
{

#if defined(NOMAKE_WINDOWS)
	void *module;

	wchar_t buffer[64];
	UNICODE_STRING string;
	unsigned long status;

	string.length = 12 * sizeof(wchar_t);
	string.maximum_length = 64 * 2;
	string.buffer = L"kernel32.dll";

	//LdrGetDllHandle();

	status = LdrLoadDll(filePath, 0, &string, &module);

#elif defined(NOMAKE_LINUX)
	dlopen(filename, flags);

#endif

	return 0;
}


void __stdcall nm_lib_unload(nm_lib_t *lib)
{
#if defined(NOMAKE_WINDOWS)
	LdrUnloadDll(lib->handle);

#elif defined(NOMAKE_LINUX)
	dlclose();
#endif
}


void __stdcall nm_lib_load_symbol()
{

#if defined(NOMAKE_WINDOWS)
	//LdrGetProcedureAddress();

#elif defined(NOMAKE_LINUX)
	dlsym(handle, symbol);
#endif
}

void __stdcall nm_load_symbol_batch(const char *lib, nm_symbol_batch *table)
{

}


nm_stopwatch_t * __stdcall nm_stopwatch_new(nm_app_t *app)
{
	nm_stopwatch_t * stopwatch = 0;

	stopwatch = nm_malloc(sizeof(nm_stopwatch_t));
	if(!stopwatch)
	{
		// error: out of memory
		return stopwatch;
	}

	stopwatch->app = app;
	stopwatch->watch = 0;
	return stopwatch;
}


void __stdcall nm_stopwatch_start(nm_stopwatch_t *stopwatch)
{
#if defined(NOMAKE_WINDOWS)
	NtQueryPerformanceCounter(&stopwatch->counter, &stopwatch->frequency);
#endif
}


nm_timediff_t *__stdcall nm_stopwatch_stop(nm_stopwatch_t *stopwatch)
{
#if defined(NOMAKE_WINDOWS)
	NtQueryPerformanceCounter(&stopwatch->counter, &stopwatch->frequency);
#endif
	return 0;
}


void __stdcall nm_stopwatch_reset(nm_stopwatch_t *stopwatch)
{
	stopwatch->watch = 0;
}


void __stdcall nm_stopwatch_destroy(nm_stopwatch_t *stopwatch)
{
	nm_free(stopwatch);
}


/*
void nm_syscall(int n)
{
	asm {
		mov eax, nj
	};
}
*/


const char *project_template =
"{\"";


void __cdecl nm_parse_json_config_file()
{

	
/*
	int count = 0;
	const char *string = "{\"hello\" : 1}";
	size_t length = strlen(string);

	jsmn_parser parser;

	jsmntok_t tokens[128];

	jsmn_init(&parser);

	count = jsmn_parse(&parser, string, length, tokens, 128);

*/

}




// 32 bit
/*
#if defined(NOMAKE_32BIT)
	#define NtCurrentTeb() (TEB*)__readfsdword(0x18);
#elif defined(NOMAKE_64BIT)
	#define NtCurrentTeb() (TEB*)__readgsqword(0x30);
#endif
*/



unsigned long __stdcall NtCreateIoCompletion2
	(void **IoCompletionHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES *ObjectAttributes,
	unsigned long Count);







#include "win32sys.c"
#include "win32.c"


#include "dir.c"


bool __stdcall nm_file_exists(wchar_t *absolute_path)
{
#if defined(NOMAKE_WINDOWS)
	return false;
#endif
}





/**
 * if there is a directory provided, the fileaname should be a relative
 * file path, otherwise it should be an absolute path
 * file will not be created until a write is done on the file
*/
nm_file_t * __stdcall nm_file_open(
	nm_app_t *app,
	nm_dir_t *dir, //optional
	char *name,
	uint32_t length)
{
#if defined(NOMAKE_WINDOWS)
	nm_file_t *file = 0;


	//allocate nm_file_t here
	file = nm_malloc(sizeof(nm_file_t));
	if(!file)
	{
		// error: out of memory
	}


/*
	oa.ObjectName = 0;
	access.mask = 0;
	status = NtCreateEvent(&file->event, access, &oa,
		NotificationEvent, false);
	if(status > 0){
		LogMessageW(L"NtCreateEvent failed: 0x%1!x!\n", status);
		return 0;
	}
*/


	void *fileHandle;
	void *dirHandle = 0;

	if(dir)
	{
		dirHandle = dir->handle;
		dir->refCount++;
	}

	fileHandle = win32OpenFile(dirHandle, name, length);
	if(!fileHandle)
	{
		// file does not exist, fill struct
		file->isWritten = false;
	}
	else
	{
		// file exist, fill struct
		file->isWritten = true;
	}

	file->handle = fileHandle;
	file->name = 0;

	return file;
#endif
}


nm_dir_t * __stdcall nm_file_get_dir(nm_file_t *file)
{
	nm_dir_t *dir = 0;
	IO_STATUS_BLOCK ioStatusBlock;
	unsigned long status;

	wchar_t *filename, *ptr;
	unsigned long length;

	uint8_t buffer[512];
	FILE_NAME_INFORMATION *fileNameInfo = (FILE_NAME_INFORMATION*)buffer;

	if(file->dir)
	{
		return file->dir;
	}

	// get the complete path
	if(file->name)
	{

	}
	else
	{
		status = NtQueryInformationFile(
			file->handle,
			&ioStatusBlock,
			buffer,
			sizeof(buffer),
			FileNameInformation);
		if(status)
		{
			// error: could not get name info
		}
		filename = fileNameInfo->FileName;
		length = fileNameInfo->FileNameLength >> 1;

		LogMessageW(L"FileName: %1!.*s!\n", length, filename);
	}

	// TODO Need to save file name here
	// trim the file name off
	LogMessageW(L"HERE\n");
	ptr = filename + length;

	LogMessageW(L"CHAR: %1!c!\n", *(ptr-2));	

	while(*ptr != L'\\') ptr--;
	*ptr = L'\0';

	length = ptr - filename;

	LogMessageW(L"Directory: %1!.*s!\n",
		length, filename);


	// use the dir to obtain a dir handle
	//status = NtCreateFile(
	//win32OpenDir();

	return dir;
}


void __stdcall nm_file_close()
{
#if defined(NOMAKE_WINDOWS)
	//NtClose();
#endif
}



/**
 * Synchronously read a file into a buffer. This function does not return until
 * the io read has completed.
*/
void __stdcall nm_file_read(nm_file_t *file, char *buffer, size_t bufsize)
{
#if defined(NOMAKE_WINDOWS)
	if(!file->isWritten)
	{	
		// no file, exit
	}

	//win32_read_file();

#endif
}


typedef int (__cdecl *file_read_callback_t)();


/**
 * Asynchronously read a file and
*/
void __stdcall nm_file_read_async(nm_file_t *file,
		file_read_callback_t callback, void *arg)
{

}


/**
*/
void __stdcall nm_file_write(nm_file_t *file, void *buffer, size_t bufsize)
{
#if defined(NOMAKE_WINDOWS)
	if(!file->isWritten)
	{
		// create the file here	

		// TODO Where are we getting the
		// directory info and file name info from?
		//win32CreateFile(
		file->isWritten = true;
	}
#endif
}


void __stdcall nm_file_write_async(nm_file_t *file)
{

#if defined(NOMAKE_WINDOWS)
	//NtWriteFile(file->handle, file->event, 0, 0

#endif
}


char mempool[32] =
{
	0x00000002, // 2
	0x00000004, // 4
	0x00000008, // 8
	0x00000010, // 16
	0x00000020, // 32
	0x00000040, // 64
	0x00000080, // 128
	0x00000100, // 256

	0x00000200, // 512
	0x00000400, // 1024
	0x00000800, // 2048
	0x00001000, // 4096
	0x00002000, // 8192
	0x00004000, // 16384
	0x00008000, // 32768
	0x00010000, // 65536

	0x00020000, // 131072
	0x00040000, // 262144
	0x00080000, // 524288
	0x00100000, // 1048576
	0x00200000, // 2097152
	0x00400000, // 4194304
	0x00800000, // 8388608
	0x01000000, // 16777216

	0x02000000, // 33554432
	0x04000000, // 67108864
	0x08000000, // 134217728
	0x10000000, // 268435456
	0x20000000, // 536870912
	0x40000000, // 1073741824
	0x80000000, // 2147483648
	0x100000000, // 4294967296
};



PEB * __stdcall getPEB(void * processHandle)
{
	PROCESS_BASIC_INFORMATION processInfo;
	unsigned long returnLength;
	unsigned long status;

	PEB *peb = 0;

	if(!processHandle) processHandle = NtCurrentProcess();

	status = NtQueryInformationProcess(
		processHandle,
		ProcessBasicInformation,
		&processInfo,
		sizeof(processInfo),
		&returnLength);
	if(status > 0)
	{
		LogMessageW(L"NtQueryInformationProcess failed: 0x%1!x!\n", status);
		return 0;
	}



/*
	LogMessageW(L"ExitStatus: %1!u!\n", processInfo.ExitStatus);

	LogMessageW(L"PEB.UniqueProcessId: 0x%1!x!\n",
		processInfo.UniqueProcessId);

	LogMessageW(L"PEB.InheritedFromUniqueProcessId: 0x%1!x!\n",
		processInfo.InheritedFromUniqueProcessId);

	LogMessageW(L"PEB: 0x%1!x!\n", processInfo.PebBaseAddress);
*/
	return processInfo.PebBaseAddress;
}

void __stdcall displayPEB(PEB *peb)
{

	LogMessageW(L"PEB ptr: 0x%1!p!\n", peb);
	LogMessageW(L"ProcessParametersPtr: 0x%1!p!\n", peb->ProcessParameters);
	LogMessageW(L"ImagePath ptr: 0x%1!p!\n",
		peb->ProcessParameters->ImagePathName);
	LogMessageW(L"CommandLine ptr: 0x%1!p!\n",
		peb->ProcessParameters->CommandLine);
}


void __stdcall processCommandLine(wchar_t *cmdline, unsigned long length)
{
	
	LogMessageW(L"Command Line: %1!.*s!\n", length, cmdline);
}


void * connectConsole()
{
	unsigned long status;
	void *console;

	ACCESS_MASK access;
	IO_STATUS_BLOCK iosb = {0};
	OBJECT_ATTRIBUTES oa = {0};
	UNICODE_STRING path;
	LARGE_INTEGER offset = {0};

	//RtlInitUnicodeString(&path, L"\\Device\\ConDrv\\Console");
	//RtlInitUnicodeString(&path, L"\\Device\\ConDrv\\CurrentOut");
	RtlInitUnicodeString(&path, L"\\Device\\ConDrv\\Connect");
	oa.SizeOf = sizeof(oa);
	//oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.ObjectName = &path;
	
	//THIS SHOULD SPECIFY WRITE PERMISSIONS
	//access.mask = STANDARD_RIGHTS_REQUIRED | FILE_WRITE_DATA; 
	access.mask =
		SYNCHRONIZE
		//|FILE_READ_DATA
		|FILE_WRITE_DATA
		//|FILE_APPEND_DATA
		//|FILE_WRITE_ATTRIBUTES
		; 

	// open the standard output handle (default is console)
	status = NtOpenFile(&console, access, &oa, &iosb, 0, 0);
	if(status > 0){
		LogMessageW(L"NtOpenFile failed: 0x%1!x!\n", status);
		return 0;
	}

/*
	// write to the standard output handle
	status = NtWriteFile(console, 0, 0, 0, &iosb, out, length, &offset, 0);
	if(status > 0){
		if(status != WINNT_STATUS_PENDING){
			LogMessageW(L"NtWriteFile failed: 0x%1!x!\n", status);
			return;
		}
		else {
			// sleep?
		}
	}
*/

	// close the handle
	//NtClose(console);

	return console;
}



#if defined(SUBSYSTEM_NATIVE)



void __stdcall nm_system_entry(PEB * peb)
{

	NtTerminateProcess(NtCurrentProcess(), 1);
}

#elif defined(SUBSYSTEM_WINDOWS)


unsigned int __stdcall nm_system_entry()
{
	LogMessageW(L"SUBSYSTEM_WINDOWS\n");
	nm_app_t *app = nm_init();
	

	
	UNICODE_STRING *str = &peb->ProcessParameters->CommandLine;
	processCommandLine(str->buffer, str->length);


	//connectConsole();
	
	nm_printf("Hello World: %u\n", 18);


	//nm_lib_load(L"C:\\Windows\\System32");


	nm_dir_t *dir;
	nm_file_t *file;

	dir = nm_dir_open(app, "\\??\\C:\\Users\\GAR1\\Documents", -1);
	if(!dir)
	{
		//error: could not open dir
		LogMessageW(L"Could not open directory\n");
		return 1;
	}

	nm_dir_traverse(dir, 0, 0);

	file = nm_file_open(app, dir, "allprojects.txt", 15);

	nm_file_get_dir(file);


	nm_timer_new(app);


/**
 * Project templates are JSON files that describe the bare-bones
 * structure of a project including the directory hierarchy and
 * file templates.
 * 
*/

	//nm_json_parse();


	return 0;
}

#elif defined(SUBSYSTEM_CONSOLE)


bool traverseFiles(void *ctx, unsigned long fileNameLength, wchar_t *fileName)
{
	LogMessageW(L"File: %1!.*s!\n", fileNameLength, fileName);
	return true;
}


bool traverseDirs(void *ctx, unsigned long fileNameLength, wchar_t *fileName)
{
	LogMessageW(L"Directory: %1!.*s!\n", fileNameLength, fileName);
	return true;
}


#include "net.c"


int __stdcall testProc(int n1);



unsigned int __stdcall nm_system_entry(int arg, char **argv)
{
	LogMessageW(L"SUBSYSTEM_CONSOLE\n");
	nm_app_t *app = nm_init();
	

	//LogMessageA("TESTPROC %1!u!\n", testProc(5));


	//connectConsole();
	
	nm_printf("Hello World: %u\n", 18);


	//nm_lib_load(L"C:\\Windows\\System32");


	nm_dir_t *dir;
	nm_file_t *file;

/*
	dir = nm_dir_open(app, "\\??\\C:\\Users\\GAR1\\Documents", -1);
	if(!dir)
	{
		//error: could not open dir
		LogMessageW(L"Could not open directory\n");
		return 1;
	}
*/

	//nm_dir_traverse(dir, 0, 0);

//	file = nm_file_open(app, dir, "allprojects.txt", 15);

//	nm_file_get_dir(file);

	struct WinSystem System = {0};
	struct WinDir Dir;

	Dir.parentDirHandle = NULL;
	Dir.path = "\\??\\C:\\Users\\GAR1\\Documents";
	Dir.pathLength = -1;

	Dir.traverseFiles = traverseFiles;
	Dir.traverseDirs = traverseDirs;

	Dir.context = 0;

	openSystem(&System);

	if(openDir(&System, &Dir))
	{
		getDirectoryFiles(&Dir);
	}

	closeDir(&Dir);


	nm_net_init(0);


	//nm_timer_new(app);


/**
 * Project templates are JSON files that describe the bare-bones
 * structure of a project including the directory hierarchy and
 * file templates.
 * 
*/

	//nm_json_parse();


	return 0;
}




#endif

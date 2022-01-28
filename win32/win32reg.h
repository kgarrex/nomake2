
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


typedef struct _KEY_VALUE_FULL_INFORMATION
{
	unsigned long TitleIndex;
	unsigned long Type;
	unsigned long DataOffset;
	unsigned long DataLength;
	unsigned long NameLength;
	wchar_t Name[1];
} KEY_VALUE_FULL_INFORMATION;


typedef struct _KEY_VALUE_PARTIAL_INFORMATION
{
	unsigned long TitleIndex;
	unsigned long Type;
	unsigned long DataLength;
	char Data[1];
} KEY_VALUE_PARTIAL_INFORMATION;



// Returns a value entry for a registry key
unsigned long __stdcall NtQueryValueKey(
	void *KeyHandle,
	UNICODE_STRING *ValueName,
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	void *KeyValueInformation,
	unsigned long Length,
	unsigned long *ResultLength);


// Gets information about the value entries of an open key.
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



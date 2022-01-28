

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;



typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation
} SECTION_INFORMATION_CLASS;


typedef struct _SECTION_IMAGE_INFORMATION {
	void *TransferAddress;
	unsigned long ZeroBits;
	unsigned long MaximumStackSize;
	unsigned long CommittedStackSize;
	unsigned long SubSystemType;
	union {
		struct {
			short SubSystemMinorVersion;
			short SubSystemMajorVersion;	
		};
		unsigned long SubSystemVersion;
	};
	unsigned long GpValue;
	short ImageCharacteristics;
	short DllCharacteristics;
	short Machine;
	unsigned char ImageContainsCode;
	unsigned char ImageFlags;
	unsigned long ComPlusNativeReady:1;
	unsigned long ComPlusILOnly:1;
	unsigned long ImageDynamicallyRelocated:1;
	unsigned long Reserved:5;
	unsigned long LoaderFlags;
	unsigned long ImageFileSize;
	unsigned long CheckSum;
} SECTION_IMAGE_INFORMATION;



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






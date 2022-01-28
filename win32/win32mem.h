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



// Dynamically extend the size of the section
#define SECTION_EXTEND_SIZE  0x0010

// Execute views of the section
#define SECTION_MAP_EXECUTE  0x0008

// Read views of the section
#define SECTION_MAP_READ     0x0004

// Write views of the section
#define SECTION_MAP_WRITE    0x0002

// Query the section object for information about the section.
// Drivers should set this flag.
#define SECTION_QUERY        0x0001



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





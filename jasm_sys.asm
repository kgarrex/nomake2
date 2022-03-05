
;IF WINDOWS

;****************************************************
;
; NTSTATUS NtAllocateVirtualMemory(
;     [in]    HANDLE ProcessHandle,
;     [inout] PVOID *BaseAddress,
;     [in]    ULONG_PTR ZeroBits,
;     [inout] PSIZE_T RegionSize,
;     [in]    ULONG AllocationType,
;     [in]    ULONG Protect);
;
;****************************************************
NtAllocateVirtualMemory:




;****************************************************
;
; NTSTATUS NtFreeVirtualMemory(
;     [in]    HANDLE ProcessHandle,
;     [inout] PVOID *BaseAddress,
;     [inout] PSIZE_T RegionSize,
;     [in]    ULONG FreeType);
;
;****************************************************
NtFreeVirtualMemory:




;****************************************************
;
; NTSTATUS NtCreateFile(
;     [out]   PHANDLE FileHandle,
;     [in]    ACCESS_MASK DesiredAccess,
;     [in]    POBJECT_ATTRIBUTES ObjectAttributes,
;     [out]   PIO_STATUS_BLOCK IoStatusBlock,
;     [inopt] PLARGE_INTEGER AllocationSize,
;     [in]    ULONG FileAttributes,
;     [in]    ULONG ShareAccess,
;     [in]    ULONG CreateDisposition,
;     [in]    ULONG CreateOptions,
;     [in]    ULONG EaBuffer,
;     [in]    ULONG EaLength);
;
;****************************************************
NtCreateFile:





;****************************************************
;
; NTSTATUS NtDeleteFile(
;     [in]    POBJECT_ATTRIBUTES ObjectAttributes);
;
;****************************************************
NtDeleteFile:




;ELSEIF UNIX/LINUX/BSD

;****************************************************
;
; void *sbrk(void *addr);
;
;****************************************************
sbrk:

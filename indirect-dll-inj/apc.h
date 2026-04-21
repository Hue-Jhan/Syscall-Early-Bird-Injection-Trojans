#pragma once
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <winbase.h>
#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define PRINTXD(FUNCTION_NAME, NTSTATUS_ERROR)                        \
    do {                                                                  \
        fprintf(stderr, FUNCTION_NAME " line %d, error: 0x%lx\n", __LINE__, NTSTATUS_ERROR);                      \
    } while (0)

typedef LONG NTSTATUS;
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define OBJ_CASE_INSENSITIVE 0x00000040L

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef const UNICODE_STRING* PCUNICODE_STRING;
typedef const OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;
typedef struct _INITIAL_TEB {
    struct {
        PVOID OldStackBase;     // Pointer to the base address of the previous stack.
        PVOID OldStackLimit;    // Pointer to the limit address of the previous stack.
    } OldInitialTeb;
    PVOID StackBase;            // Pointer to the base address of the new stack.
    PVOID StackLimit;           // Pointer to the limit address of the new stack.
    PVOID StackAllocationBase;  // Pointer to the base address where the stack was allocated.
} INITIAL_TEB, * PINITIAL_TEB;
typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, * PSTRING, ANSI_STRING, * PANSI_STRING, OEM_STRING, * POEM_STRING;
#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}
#endif
#ifndef _In_
#define _In_
#endif
#ifndef _Out_opt_
#define _Out_opt_
#endif
#ifndef _Out_writes_bytes_opt_
#define _Out_writes_bytes_opt_(x)
#endif
#define RTL_MAX_DRIVE_LETTERS 32
#define SystemThreadInformation 6
#define PS_ATTRIBUTE_NUMBER_MASK    0x0000FFFF
#define PS_ATTRIBUTE_THREAD         0x00010000 // Attribute for thread
#define PS_ATTRIBUTE_INPUT          0x00020000 // Attribute is input only
#define PS_ATTRIBUTE_ADDITIVE       0x00040000
#define PS_ATTRIBUTE_IMAGE_NAME PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED 0x01
#define PsAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
    ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;    // This is the "ID" (e.g., PsAttributeImageName)
    SIZE_T Size;
    union {
        ULONG_PTR Value;    // This is the member your compiler is missing
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;
typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1]; // Flexible array member
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;
typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;
typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;
typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags; // RTL_USER_PROC_FLAGS
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags; // RTL_USER_PROC_CONSOLE_FLAGS
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags; // RTL_USER_PROC_WINDOW_FLAGS
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;

    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads; // THRESHOLD
    UNICODE_STRING RedirectionDllName; // REDSTONE5
    UNICODE_STRING HeapPartitionName; // 19H1
    PULONGLONG DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum; // 20H1
    ULONG HeapMemoryTypeMask;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;
typedef enum _PS_ATTRIBUTE_NUM {
    PsAttributeParentProcess,                   // in HANDLE
    PsAttributeDebugObject,                     // in HANDLE
    PsAttributeToken,                           // in HANDLE
    PsAttributeClientId,                        // out PCLIENT_ID
    PsAttributeTebAddress,                      // out PTEB*
    PsAttributeImageName,                       // in PWSTR
    PsAttributeImageInfo,                       // out PSECTION_IMAGE_INFORMATION
    PsAttributeMemoryReserve,                   // in PPS_MEMORY_RESERVE
    PsAttributePriorityClass,                   // in UCHAR
    PsAttributeErrorMode,                       // in ULONG
    PsAttributeStdHandleInfo,                   // in PPS_STD_HANDLE_INFO // 10
    PsAttributeHandleList,                      // in HANDLE[]
    PsAttributeGroupAffinity,                   // in PGROUP_AFFINITY
    PsAttributePreferredNode,                   // in PUSHORT
    PsAttributeIdealProcessor,                  // in PPROCESSOR_NUMBER
    PsAttributeUmsThread,                       // in PUMS_CREATE_THREAD_ATTRIBUTES
    PsAttributeMitigationOptions,               // in PPS_MITIGATION_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_POLICY_*) // since WIN8
    PsAttributeProtectionLevel,                 // in PS_PROTECTION // since WINBLUE
    PsAttributeSecureProcess,                   // in PPS_TRUSTLET_CREATE_ATTRIBUTES // since THRESHOLD
    PsAttributeJobList,                         // in HANDLE[]
    PsAttributeChildProcessPolicy,              // in PULONG (PROCESS_CREATION_CHILD_PROCESS_*) // since THRESHOLD2 // 20
    PsAttributeAllApplicationPackagesPolicy,    // in PULONG (PROCESS_CREATION_ALL_APPLICATION_PACKAGES_*) // since REDSTONE
    PsAttributeWin32kFilter,                    // in PWIN32K_SYSCALL_FILTER
    PsAttributeSafeOpenPromptOriginClaim,       // in SE_SAFE_OPEN_PROMPT_RESULTS
    PsAttributeBnoIsolation,                    // in PPS_BNO_ISOLATION_PARAMETERS // since REDSTONE2
    PsAttributeDesktopAppPolicy,                // in PULONG (PROCESS_CREATION_DESKTOP_APP_*)
    PsAttributeChpe,                            // in BOOLEAN // since REDSTONE3
    PsAttributeMitigationAuditOptions,          // in PPS_MITIGATION_AUDIT_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_AUDIT_POLICY_*) // since 21H1
    PsAttributeMachineType,                     // in USHORT // since 21H2
    PsAttributeComponentFilter,                 // in COMPONENT_FILTER
    PsAttributeEnableOptionalXStateFeatures,    // in ULONG64 // since WIN11 // 30
    PsAttributeSupportedMachines,               // in ULONG // since 24H2
    PsAttributeSveVectorLength,                 // in PPS_PROCESS_CREATION_SVE_VECTOR_LENGTH
    PsAttributeMax
} PS_ATTRIBUTE_NUM;
typedef struct _SECTION_IMAGE_INFORMATION {
    PVOID TransferAddress;          // The address of the image entry point function.
    ULONG ZeroBits;                 // The number of high-order address bits that must be zero in the image base address.
    SIZE_T MaximumStackSize;        // The maximum stack size of threads from the PE file header.
    SIZE_T CommittedStackSize;      // The initial stack size of threads from the PE file header.
    ULONG SubSystemType;            // The image subsystem from the PE file header (e.g., Windows GUI, Windows CUI, POSIX).
    union {
        struct {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        };
        ULONG SubSystemVersion;
    };
    union {
        struct {
            USHORT MajorOperatingSystemVersion;
            USHORT MinorOperatingSystemVersion;
        };
        ULONG OperatingSystemVersion;
    };
    USHORT ImageCharacteristics;    // The image characteristics from the PE file header.
    USHORT DllCharacteristics;      // The DLL characteristics flags (e.g., ASLR, NX compatibility).
    USHORT Machine;                 // The image architecture (e.g., x86, x64, ARM).
    BOOLEAN ImageContainsCode;      // The image contains native executable code.
    union {
        UCHAR ImageFlags;
        struct {
            UCHAR ComPlusNativeReady : 1;           // The image contains precompiled .NET assembly generated by NGEN (Native Image Generator).
            UCHAR ComPlusILOnly : 1;                // the image contains only Microsoft Intermediate Language (IL) assembly.
            UCHAR ImageDynamicallyRelocated : 1;    // The image was mapped using a random base address rather than the preferred base address.
            UCHAR ImageMappedFlat : 1;              // The image was mapped using a single contiguous region, rather than separate regions for each section.
            UCHAR BaseBelow4gb : 1;                 // The image was mapped using a base address below the 4 GB boundary.
            UCHAR ComPlusPrefer32bit : 1;           // The image prefers to run as a 32-bit process, even on a 64-bit system.
            UCHAR Reserved : 2;
        };
    };
    ULONG LoaderFlags;               // Reserved by ntdll.dll for the Windows loader.
    ULONG ImageFileSize;             // The size of the image, in bytes, including all headers.
    ULONG CheckSum;                  // The image file checksum, from the PE optional header.
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

typedef _Function_class_(PS_APC_ROUTINE)
VOID NTAPI PS_APC_ROUTINE(_In_opt_ PVOID ApcArgument1, _In_opt_ PVOID ApcArgument2, _In_opt_ PVOID ApcArgument3);
typedef PS_APC_ROUTINE* PPS_APC_ROUTINE;
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
typedef enum _PS_CREATE_STATE {
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName, // Debugger specified
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;
_Struct_size_bytes_(Size)
typedef struct _PS_CREATE_INFO {
    SIZE_T Size;
    PS_CREATE_STATE State;
    union {
        // PsCreateInitialState
        struct {
            union {
                ULONG InitFlags;
                struct {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeFormat
        struct {
            USHORT DllCharacteristics;
        } ExeFormat;

        // PsCreateFailExeName
        struct {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct {
            union {
                ULONG OutputFlags;
                struct {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, * PPS_CREATE_INFO;
typedef struct _RTL_USER_PROCESS_INFORMATION {
    ULONG Length;
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, * PRTL_USER_PROCESS_INFORMATION;

DWORD h_NtOpenProcessSSN;
DWORD h_NtAllocateVirtualMemorySSN;
DWORD h_NtWriteVirtualMemorySSN;
DWORD h_NtProtectVirtualMemorySSN;
DWORD h_NtWaitForSingleObjectSSN;
DWORD h_NtFreeVirtualMemorySSN;
DWORD h_NtCloseSSN;
DWORD h_NtResumeThreadSSN;
DWORD h_NtQuerySystemInformationSSN;
DWORD h_NtOpenThreadSSN;
DWORD h_NtQueueApcThreadSSN;

DWORD h_NtCreateUserProcessSSN;

extern NTSTATUS NtOpenProcess(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId OPTIONAL);
extern NTSTATUS NtOpenThread(OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId OPTIONAL);
extern NTSTATUS NtAllocateVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);
extern NTSTATUS NtProtectVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtect, _Out_ PULONG OldProtect);
extern NTSTATUS NtWriteVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN SIZE_T NumberOfBytesToWrite, OUT PSIZE_T NumberOfBytesWritten OPTIONAL);
extern NTSTATUS NtWaitForSingleObject(_In_ HANDLE Handle, _In_ BOOLEAN Alertable, _In_opt_ PLARGE_INTEGER Timeout);
extern NTSTATUS NtFreeVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PSIZE_T RegionSize, _In_ ULONG FreeType);
extern NTSTATUS NtClose(IN HANDLE Handle);
extern NTSTATUS NtResumeThread(_In_ HANDLE ThreadHandle, _Out_opt_ PULONG PreviousSuspendCount);
extern NTSTATUS NtQueueApcThread(_In_ HANDLE ThreadHandle, _In_ PPS_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcArgument1, _In_opt_ PVOID ApcArgument2, _In_opt_ PVOID ApcArgument3);
extern NTSTATUS NtCreateUserProcess(_Out_ PHANDLE ProcessHandle, _Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK ProcessDesiredAccess, _In_ ACCESS_MASK ThreadDesiredAccess, _In_opt_ PCOBJECT_ATTRIBUTES ProcessObjectAttributes, _In_opt_ PCOBJECT_ATTRIBUTES ThreadObjectAttributes, _In_ ULONG ProcessFlags, _In_ ULONG ThreadFlags, _In_opt_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters, _Inout_ PPS_CREATE_INFO CreateInfo, _In_opt_ PPS_ATTRIBUTE_LIST AttributeList);

typedef VOID(NTAPI* xd_RtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI* xd_RtlCreateProcessParametersEx)(PRTL_USER_PROCESS_PARAMETERS*, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, ULONG);
typedef NTSTATUS(NTAPI* xd_RtlCreateUserProcess)(_In_ PUNICODE_STRING NtImagePathName, _In_ ULONG Attributes, _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters, _In_opt_ PSECURITY_DESCRIPTOR ProcessSecurityDescriptor, _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor, _In_opt_ HANDLE ParentProcess, _In_ BOOLEAN InheritHandles, _In_opt_ HANDLE DebugPort, _In_opt_ HANDLE TokenHandle, _Out_ PRTL_USER_PROCESS_INFORMATION ProcessInformation);

UINT_PTR GetNtFunctionAddress(LPCSTR FunctionName, HMODULE ModuleHandle);

extern xd_RtlInitUnicodeString RtlInitUnicodeString;
extern xd_RtlCreateProcessParametersEx RtlCreateProcessParametersEx;
extern xd_RtlCreateUserProcess RtlCreateUserProcess;


typedef LONG KPRIORITY, * PKPRIORITY;
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;
typedef enum _KWAIT_REASON {
    Executive,               // Waiting for an executive event.
    FreePage,                // Waiting for a free page.
    PageIn,                  // Waiting for a page to be read in.
    PoolAllocation,          // Waiting for a pool allocation.
    DelayExecution,          // Waiting due to a delay execution.           // NtDelayExecution
    Suspended,               // Waiting because the thread is suspended.    // NtSuspendThread
    UserRequest,             // Waiting due to a user request.              // NtWaitForSingleObject
    WrExecutive,             // Waiting for an executive event.
    WrFreePage,              // Waiting for a free page.
    WrPageIn,                // Waiting for a page to be read in.
    WrPoolAllocation,        // Waiting for a pool allocation.              // 10
    WrDelayExecution,        // Waiting due to a delay execution.
    WrSuspended,             // Waiting because the thread is suspended.
    WrUserRequest,           // Waiting due to a user request.
    WrEventPair,             // Waiting for an event pair.                  // NtCreateEventPair
    WrQueue,                 // Waiting for a queue.                        // NtRemoveIoCompletion
    WrLpcReceive,            // Waiting for an LPC receive.                 // NtReplyWaitReceivePort
    WrLpcReply,              // Waiting for an LPC reply.                   // NtRequestWaitReplyPort
    WrVirtualMemory,         // Waiting for virtual memory.
    WrPageOut,               // Waiting for a page to be written out.       // NtFlushVirtualMemory
    WrRendezvous,            // Waiting for a rendezvous.                   // 20
    WrKeyedEvent,            // Waiting for a keyed event.                  // NtCreateKeyedEvent
    WrTerminated,            // Waiting for thread termination.
    WrProcessInSwap,         // Waiting for a process to be swapped in.
    WrCpuRateControl,        // Waiting for CPU rate control.
    WrCalloutStack,          // Waiting for a callout stack.
    WrKernel,                // Waiting for a kernel event.
    WrResource,              // Waiting for a resource.
    WrPushLock,              // Waiting for a push lock.
    WrMutex,                 // Waiting for a mutex.
    WrQuantumEnd,            // Waiting for the end of a quantum.           // 30
    WrDispatchInt,           // Waiting for a dispatch interrupt.
    WrPreempted,             // Waiting because the thread was preempted.
    WrYieldExecution,        // Waiting to yield execution.
    WrFastMutex,             // Waiting for a fast mutex.
    WrGuardedMutex,          // Waiting for a guarded mutex.
    WrRundown,               // Waiting for a rundown.
    WrAlertByThreadId,       // Waiting for an alert by thread ID.
    WrDeferredPreempt,       // Waiting for a deferred preemption.
    WrPhysicalFault,         // Waiting for a physical fault.
    WrIoRing,                // Waiting for an I/O ring.                    // 40
    WrMdlCache,              // Waiting for an MDL cache.
    WrRcu,                   // Waiting for read-copy-update (RCU) synchronization.
    MaximumWaitReason
} KWAIT_REASON, * PKWAIT_REASON;
typedef enum _KTHREAD_STATE {
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWaitObsolete,
    WaitingForProcessInSwap,
    MaximumThreadState
} KTHREAD_STATE, * PKTHREAD_STATE;
typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;                   // Number of 100-nanosecond intervals spent executing kernel code.
    LARGE_INTEGER UserTime;                     // Number of 100-nanosecond intervals spent executing user code.
    LARGE_INTEGER CreateTime;                   // The date and time when the thread was created.
    ULONG WaitTime;                             // The current time spent in ready queue or waiting (depending on the thread state).
    PVOID StartAddress;                         // The initial start address of the thread.
    CLIENT_ID ClientId;                         // The identifier of the thread and the process owning the thread.
    KPRIORITY Priority;                         // The dynamic priority of the thread.
    KPRIORITY BasePriority;                     // The starting priority of the thread.
    ULONG ContextSwitches;                      // The total number of context switches performed.
    KTHREAD_STATE ThreadState;                  // The current state of the thread.
    KWAIT_REASON WaitReason;                    // The current reason the thread is waiting.
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;
_Struct_size_bytes_(NextEntryOffset)
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;                      // The address of the previous item plus the value in the NextEntryOffset member. For the last item in the array, NextEntryOffset is 0.
    ULONG NumberOfThreads;                      // The NumberOfThreads member contains the number of threads in the process.
    ULONGLONG WorkingSetPrivateSize;            // The total private memory that a process currently has allocated and is physically resident in memory. // since VISTA
    ULONG HardFaultCount;                       // The total number of hard faults for data from disk rather than from in-memory pages. // since WIN7
    ULONG NumberOfThreadsHighWatermark;         // The peak number of threads that were running at any given point in time, indicative of potential performance bottlenecks related to thread management.
    ULONGLONG CycleTime;                        // The sum of the cycle time of all threads in the process.
    LARGE_INTEGER CreateTime;                   // Number of 100-nanosecond intervals since the creation time of the process. Not updated during system timezone changes.
    LARGE_INTEGER UserTime;                     // Number of 100-nanosecond intervals the process has executed in user mode.
    LARGE_INTEGER KernelTime;                   // Number of 100-nanosecond intervals the process has executed in kernel mode.
    UNICODE_STRING ImageName;                   // The file name of the executable image.
    KPRIORITY BasePriority;                     // The starting priority of the process.
    HANDLE UniqueProcessId;                     // The identifier of the process.
    HANDLE InheritedFromUniqueProcessId;        // The identifier of the process that created this process. Not updated and incorrectly refers to processes with recycled identifiers. 
    ULONG HandleCount;                          // The current number of open handles used by the process.
    ULONG SessionId;                            // The identifier of the Remote Desktop Services session under which the specified process is running. 
    ULONG_PTR UniqueProcessKey;                 // since VISTA (requires SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;                     // The peak size, in bytes, of the virtual memory used by the process.
    SIZE_T VirtualSize;                         // The current size, in bytes, of virtual memory used by the process.
    ULONG PageFaultCount;                       // The total number of page faults for data that is not currently in memory. The value wraps around to zero on average 24 hours.
    SIZE_T PeakWorkingSetSize;                  // The peak size, in kilobytes, of the working set of the process.
    SIZE_T WorkingSetSize;                      // The number of pages visible to the process in physical memory. These pages are resident and available for use without triggering a page fault.
    SIZE_T QuotaPeakPagedPoolUsage;             // The peak quota charged to the process for pool usage, in bytes.
    SIZE_T QuotaPagedPoolUsage;                 // The quota charged to the process for paged pool usage, in bytes.
    SIZE_T QuotaPeakNonPagedPoolUsage;          // The peak quota charged to the process for nonpaged pool usage, in bytes.
    SIZE_T QuotaNonPagedPoolUsage;              // The current quota charged to the process for nonpaged pool usage.
    SIZE_T PagefileUsage;                       // The total number of bytes of page file storage in use by the process.
    SIZE_T PeakPagefileUsage;                   // The maximum number of bytes of page-file storage used by the process.
    SIZE_T PrivatePageCount;                    // The number of memory pages allocated for the use by the process.
    LARGE_INTEGER ReadOperationCount;           // The total number of read operations performed.
    LARGE_INTEGER WriteOperationCount;          // The total number of write operations performed.
    LARGE_INTEGER OtherOperationCount;          // The total number of I/O operations performed other than read and write operations.
    LARGE_INTEGER ReadTransferCount;            // The total number of bytes read during a read operation.
    LARGE_INTEGER WriteTransferCount;           // The total number of bytes written during a write operation.
    LARGE_INTEGER OtherTransferCount;           // The total number of bytes transferred during operations other than read and write operations.
    SYSTEM_THREAD_INFORMATION Threads[1];       // This type is not defined in the structure but was added for convenience.
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

extern NTSTATUS NtQuerySystemInformation(_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);

BOOL NtAPCinject(IN HANDLE hThread, IN PVOID pAddress, FARPROC loadLibAdd);

#pragma once
#include <ntifs.h>
#include <intrin.h>

using u64 = unsigned long long;
using u32 = unsigned long;
using u16 = unsigned short;
using u8 = unsigned char;

#define DBG_PRINT(...) DbgPrintEx( DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, "[kutils]" __VA_ARGS__);

// Export Directory
#define IMAGE_DIRECTORY_ENTRY_EXPORT         0
// Import Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT         1
// Resource Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE       2
// Exception Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION      3
// Security Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY       4
// Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_BASERELOC      5
// Debug Directory
#define IMAGE_DIRECTORY_ENTRY_DEBUG          6
// Description String
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT      7
// Machine Value (MIPS GP)
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR      8
// TLS Directory
#define IMAGE_DIRECTORY_ENTRY_TLS            9
// Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10

typedef struct _IMAGE_DOS_HEADER {  // DOS .EXE header
    USHORT e_magic;         // Magic number
    USHORT e_cblp;          // Bytes on last page of file
    USHORT e_cp;            // Pages in file
    USHORT e_crlc;          // Relocations
    USHORT e_cparhdr;       // Size of header in paragraphs
    USHORT e_minalloc;      // Minimum extra paragraphs needed
    USHORT e_maxalloc;      // Maximum extra paragraphs needed
    USHORT e_ss;            // Initial (relative) SS value
    USHORT e_sp;            // Initial SP value
    USHORT e_csum;          // Checksum
    USHORT e_ip;            // Initial IP value
    USHORT e_cs;            // Initial (relative) CS value
    USHORT e_lfarlc;        // File address of relocation table
    USHORT e_ovno;          // Overlay number
    USHORT e_res[4];        // Reserved words
    USHORT e_oemid;         // OEM identifier (for e_oeminfo)
    USHORT e_oeminfo;       // OEM information; e_oemid specific
    USHORT e_res2[10];      // Reserved words
    LONG   e_lfanew;        // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    short  Machine;
    short  NumberOfSections;
    unsigned TimeDateStamp;
    unsigned PointerToSymbolTable;
    unsigned NumberOfSymbols;
    short  SizeOfOptionalHeader;
    short  Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    unsigned VirtualAddress;
    unsigned Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    short                 Magic;
    unsigned char                 MajorLinkerVersion;
    unsigned char                 MinorLinkerVersion;
    unsigned                SizeOfCode;
    unsigned                SizeOfInitializedData;
    unsigned                SizeOfUninitializedData;
    unsigned                AddressOfEntryPoint;
    unsigned                BaseOfCode;
    ULONGLONG            ImageBase;
    unsigned                SectionAlignment;
    unsigned                FileAlignment;
    short                 MajorOperatingSystemVersion;
    short                 MinorOperatingSystemVersion;
    short                 MajorImageVersion;
    short                 MinorImageVersion;
    short                 MajorSubsystemVersion;
    short                 MinorSubsystemVersion;
    unsigned                Win32VersionValue;
    unsigned                SizeOfImage;
    unsigned                SizeOfHeaders;
    unsigned                CheckSum;
    short                 Subsystem;
    short                 DllCharacteristics;
    ULONGLONG            SizeOfStackReserve;
    ULONGLONG            SizeOfStackCommit;
    ULONGLONG            SizeOfHeapReserve;
    ULONGLONG            SizeOfHeapCommit;
    unsigned                 LoaderFlags;
    unsigned                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    unsigned                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        unsigned long   Characteristics;            // 0 for terminating null import descriptor
        unsigned long   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    unsigned long   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    unsigned long   ForwarderChain;                 // -1 if no forwarders
    unsigned long   Name;
    unsigned long   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED* PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_BY_NAME {
    unsigned long    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, * PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;  // PBYTE 
        ULONGLONG Function;         // PDWORD
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64, * PIMAGE_THUNK_DATA64;
typedef PIMAGE_THUNK_DATA64             PIMAGE_THUNK_DATA;

typedef enum _SYSTEM_INFORMATION_CLASS 
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemNextEventIdInformation,
    SystemEventIdsInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemPlugPlayBusInformation,
    SystemDockInformation
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    unsigned short LoadCount;
    unsigned short TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN                 InheritedAddressSpace;
    BOOLEAN                 ReadImageFileExecOptions;
    BOOLEAN                 BeingDebugged;
    BOOLEAN                 Spare;
    HANDLE                  Mutant;
    PVOID                   ImageBaseAddress;
    PPEB_LDR_DATA           LoaderData;
    PVOID                   ProcessParameters;
    PVOID                   SubSystemData;
    PVOID                   ProcessHeap;
    PVOID                   FastPebLock;
    PVOID                   FastPebLockRoutine;
    PVOID                   FastPebUnlockRoutine;
    ULONG                   EnvironmentUpdateCount;
    PVOID                   KernelCallbackTable;
    PVOID                   EventLogSection;
    PVOID                   EventLog;
    PVOID                   FreeList;
    ULONG                   TlsExpansionCounter;
    PVOID                   TlsBitmap;
    ULONG                   TlsBitmapBits[0x2];
    PVOID                   ReadOnlySharedMemoryBase;
    PVOID                   ReadOnlySharedMemoryHeap;
    PVOID*                  ReadOnlyStaticServerData;
    PVOID                   AnsiCodePageData;
    PVOID                   OemCodePageData;
    PVOID                   UnicodeCaseTableData;
    ULONG                   NumberOfProcessors;
    ULONG                   NtGlobalFlag;
    unsigned char           Spare2[0x4];
    LARGE_INTEGER           CriticalSectionTimeout;
    ULONG                   HeapSegmentReserve;
    ULONG                   HeapSegmentCommit;
    ULONG                   HeapDeCommitTotalFreeThreshold;
    ULONG                   HeapDeCommitFreeBlockThreshold;
    ULONG                   NumberOfHeaps;
    ULONG                   MaximumNumberOfHeaps;
    PVOID**                 ProcessHeaps;
    PVOID                   GdiSharedHandleTable;
    PVOID                   ProcessStarterHelper;
    PVOID                   GdiDCAttributeList;
    PVOID                   LoaderLock;
    ULONG                   OSMajorVersion;
    ULONG                   OSMinorVersion;
    ULONG                   OSBuildNumber;
    ULONG                   OSPlatformId;
    ULONG                   ImageSubSystem;
    ULONG                   ImageSubSystemMajorVersion;
    ULONG                   ImageSubSystemMinorVersion;
    ULONG                   GdiHandleBuffer[0x22];
    ULONG                   PostProcessInitRoutine;
    ULONG                   TlsExpansionBitmap;
    unsigned char           TlsExpansionBitmapBits[0x80];
    ULONG                   SessionId;
} PEB, * PPEB;

typedef struct _SYSTEM_THREAD
{
    LARGE_INTEGER           KernelTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           CreateTime;
    ULONG                   WaitTime;
    PVOID                   StartAddress;
    CLIENT_ID               ClientId;
    KPRIORITY               Priority;
    LONG                    BasePriority;
    ULONG                   ContextSwitchCount;
    ULONG                   State;
    KWAIT_REASON            WaitReason;
} SYSTEM_THREAD, * PSYSTEM_THREAD;

typedef struct _SYSTEM_PROCESS_INFORMATION {

    ULONG                   NextEntryOffset;
    ULONG                   NumberOfThreads;
    LARGE_INTEGER           Reserved[3];
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           KernelTime;
    UNICODE_STRING          ImageName;
    KPRIORITY               BasePriority;
    HANDLE                  ProcessId;
    HANDLE                  InheritedFromProcessId;
    ULONG                   HandleCount;
    ULONG                   Reserved2[2];
    ULONG                   PrivatePageCount;
    VM_COUNTERS             VirtualMemoryCounters;
    IO_COUNTERS             IoCounters;
    SYSTEM_THREAD           Threads[0];

} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _OBJECT_DIRECTORY_ENTRY
{
    struct _OBJECT_DIRECTORY_ENTRY* ChainLink;
    PVOID Object;
    ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, * POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY
{
    POBJECT_DIRECTORY_ENTRY HashBuckets[37];
    EX_PUSH_LOCK Lock;
    struct _DEVICE_MAP* DeviceMap;
    ULONG SessionId;
    PVOID NamespaceEntry;
    ULONG Flags;
} OBJECT_DIRECTORY, * POBJECT_DIRECTORY;

typedef struct _DEVICE_MAP
{
    POBJECT_DIRECTORY DosDevicesDirectory;
    POBJECT_DIRECTORY GlobalDosDevicesDirectory;
    ULONG ReferenceCount;
    ULONG DriveMap;
    UCHAR DriveType[32];
} DEVICE_MAP, * PDEVICE_MAP;

extern "C" NTSTATUS NtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);

extern "C" PVOID RtlFindExportedRoutineByName(
    _In_ PVOID ImageBase,
    _In_ PCCH RoutineNam
);

extern "C" PVOID PsGetProcessSectionBaseAddress(
    __in PEPROCESS Process
);

extern "C" PPEB PsGetProcessPeb(PEPROCESS Process);

namespace kutils
{
    namespace driver
    {
        inline auto get_driver_base(const char* driver_name) -> void*
        {
            u32 alloc_size{};
            NtQuerySystemInformation(
                SystemModuleInformation,
                    NULL, alloc_size, &alloc_size);

            auto module_info =
                reinterpret_cast<PRTL_PROCESS_MODULES>(
                    ExAllocatePool(NonPagedPool, alloc_size));

            NtQuerySystemInformation(
                SystemModuleInformation,
                    module_info, alloc_size, &alloc_size);

            for (auto idx = 0u; idx < module_info->NumberOfModules; ++idx)
            {
                auto module_name =
                    reinterpret_cast<const char*>(
                        module_info->Modules[idx].FullPathName +
                        module_info->Modules[idx].OffsetToFileName);

                if (!strcmp(module_name, driver_name))
                {
                    auto result = module_info->Modules[idx].ImageBase;
                    ExFreePool(module_info);
                    return result;
                }
            }

            ExFreePool(module_info);
            return nullptr;
        }

        inline auto get_driver_export(const char* driver_name, const char* routine_name) -> void*
        {
            const auto driver_base =
                get_driver_base(driver_name);

            if (!driver_base)
                return nullptr;

            return RtlFindExportedRoutineByName(
                reinterpret_cast<void*>(driver_base), routine_name);
        }

        inline auto get_driver_object(const wchar_t* driver_name) -> PDRIVER_OBJECT
        {
            HANDLE handle{};
            OBJECT_ATTRIBUTES attributes{};
            UNICODE_STRING directory_name{};
            PVOID directory{};
            BOOLEAN success = FALSE;

            RtlInitUnicodeString(&directory_name, L"\\Driver");
            InitializeObjectAttributes(
                &attributes,
                &directory_name,
                OBJ_CASE_INSENSITIVE,
                NULL,
                NULL
            );

            // open OBJECT_DIRECTORY for \\Driver
            auto status = ZwOpenDirectoryObject(
                &handle,
                DIRECTORY_ALL_ACCESS,
                &attributes
            );

            if (!NT_SUCCESS(status))
            {
                ZwClose(handle);
                return NULL;
            }

            // Get OBJECT_DIRECTORY pointer from HANDLE
            status = ObReferenceObjectByHandle(
                handle,
                DIRECTORY_ALL_ACCESS,
                nullptr,
                KernelMode,
                &directory,
                nullptr
            );

            if (!NT_SUCCESS(status))
            {
                ZwClose(handle);
                return NULL;
            }

            const auto directory_object = POBJECT_DIRECTORY(directory);
            ExAcquirePushLockExclusiveEx(&directory_object->Lock, 0);

            for (auto entry : directory_object->HashBuckets)
            {
                if (!entry) 
                    continue;

                while (entry && entry->Object)
                {
                    auto driver = PDRIVER_OBJECT(entry->Object);
                    if (!driver)
                        continue;

                    if (wcscmp(driver->DriverExtension->ServiceKeyName.Buffer, driver_name) == 0)
                        return driver;

                    entry = entry->ChainLink;
                }
            }

            ExReleasePushLockExclusiveEx(&directory_object->Lock, 0);
            ObDereferenceObject(directory);
            ZwClose(handle);
            return nullptr;
        }

        inline auto iat_hook(void* base_addr, const char* routine_name, void* func_addr) -> void*
        {
            const auto dos_headers =
                reinterpret_cast<PIMAGE_DOS_HEADER>(base_addr);

            const auto nt_headers =
                reinterpret_cast<PIMAGE_NT_HEADERS64>(
                    reinterpret_cast<DWORD_PTR>(base_addr) + dos_headers->e_lfanew);

            const auto import_dir =
                nt_headers->OptionalHeader
                .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

            auto import_des =
                reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
                    import_dir.VirtualAddress + (DWORD_PTR)base_addr);

            LPCSTR lib_name = NULL;
            PVOID result = NULL;
            PIMAGE_IMPORT_BY_NAME func_name = NULL;

            while (import_des->Name != NULL)
            {
                lib_name = (LPCSTR)import_des->Name + (DWORD_PTR)base_addr;

                if (driver::get_driver_base(lib_name))
                {
                    PIMAGE_THUNK_DATA org_first_thunk = NULL, first_thunk = NULL;
                    org_first_thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)base_addr + import_des->OriginalFirstThunk);
                    first_thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)base_addr + import_des->FirstThunk);
                    while (org_first_thunk->u1.AddressOfData != NULL)
                    {
                        func_name = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)base_addr + org_first_thunk->u1.AddressOfData);
                        if (strcmp(func_name->Name, routine_name) == 0)
                        {
                            // save old function pointer
                            result = reinterpret_cast<PVOID>(first_thunk->u1.Function);

                            //
                            // although disabling wp bit can cause crashes, im disabling it for nano seconds. only to write 8 bytes...
                            // in reality this is 1 mov instruction.
                            //
                            {
                                //
                                // disable write protection
                                //
                                _disable();
                                auto cr0 = __readcr0();
                                cr0 &= 0xfffffffffffeffff;
                                __writecr0(cr0);
                            }

                            // swap address
                            first_thunk->u1.Function = reinterpret_cast<ULONG64>(func_addr);

                            {
                                //
                                // enable write protection
                                //
                                auto cr0 = __readcr0();
                                cr0 |= 0x10000;
                                __writecr0(cr0);
                                _enable();
                            }
                            return result;
                        }
                        ++org_first_thunk;
                        ++first_thunk;
                    }
                }
                ++import_des;
            }
            return nullptr;
        }
    }

    namespace process
    {
        inline auto get_pid(const wchar_t* process_name) -> u32
        {
            u32 alloc_size{};
            NtQuerySystemInformation(
                SystemProcessInformation, 
                    nullptr, alloc_size, &alloc_size);

            auto process_info = 
                reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
                    ExAllocatePool(NonPagedPool, alloc_size));
            
            const auto orig_ptr = process_info;
            NtQuerySystemInformation(
                SystemProcessInformation, 
                    process_info, alloc_size, &alloc_size);

            while (true)
            {
                if (process_info->ImageName.Buffer)
                {
                    if (!_wcsicmp(process_info->ImageName.Buffer, process_name))
                    {
                        auto result = process_info->ProcessId;
                        ExFreePool(orig_ptr);
                        return (u32)result;
                    }
                }

                if (!process_info->NextEntryOffset)
                    break;

                process_info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
                    reinterpret_cast<u64>(process_info) + process_info->NextEntryOffset);
            }

            ExFreePool(orig_ptr);
            return NULL;
        }

        inline auto get_process_base(u32 pid) -> void*
        {
            PEPROCESS peproc;
            NTSTATUS result;

            if ((result = PsLookupProcessByProcessId((HANDLE)pid, &peproc)) == STATUS_SUCCESS)
            {
                auto base_address = 
                    PsGetProcessSectionBaseAddress(peproc);

                ObDereferenceObject(peproc);
                return base_address;
            }
            return nullptr;
        }

        inline auto get_module_base(u32 pid, const wchar_t* module_name) -> void*
        {
            PEPROCESS peproc;
            NTSTATUS result;
            KAPC_STATE apc_state;

            if ((result = PsLookupProcessByProcessId((HANDLE)pid, &peproc)) == STATUS_SUCCESS)
            {
                KeStackAttachProcess(peproc, &apc_state);
                {
                    const auto ldr_data =
                        reinterpret_cast<PPEB_LDR_DATA>(
                            PsGetProcessPeb(peproc)->LoaderData);

                    auto current_entry =
                        ldr_data->InMemoryOrderModuleList.Flink;

                    while (current_entry != &ldr_data->InMemoryOrderModuleList)
                    {
                        const auto current_entry_data =
                            reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(
                                reinterpret_cast<u64>(current_entry) - sizeof LIST_ENTRY);

                        const auto entry_module_name =
                            current_entry_data->BaseDllName.Buffer;

                        if (!_wcsicmp(entry_module_name, module_name))
                        {
                            ObDereferenceObject(peproc);
                            auto module_base = current_entry_data->DllBase;

                            KeUnstackDetachProcess(&apc_state);
                            return module_base;
                        }

                        current_entry = current_entry->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc_state);
                ObDereferenceObject(peproc);
            }
            return nullptr;
        }
    }

    namespace pe
    {
        inline auto get_nt_header(void* module_base) -> PIMAGE_NT_HEADERS64
        {
            const auto dos_header = 
                reinterpret_cast<PIMAGE_DOS_HEADER>(module_base);

            return reinterpret_cast<PIMAGE_NT_HEADERS64>(
                reinterpret_cast<u64>(module_base) + dos_header->e_lfanew);
        }
    }

    namespace signature
    {
        inline auto scan(void* base, u32 size, const char* pattern, const char* mask) -> void*
        {
            static const auto check_mask =
                [&](const char* base, const char* pattern, const char* mask) -> bool
            {
                for (; *mask; ++base, ++pattern, ++mask)
                    if (*mask == 'x' && *base != *pattern)
                        return false;
                return true;
            };

            size -= strlen(mask);
            for (auto i = 0; i <= size; ++i)
            {
                void* addr = (void*)&(((char*)base)[i]);
                if (check_mask((char*)addr, pattern, mask))
                    return addr;
            }

            return nullptr;
        }
    }
}
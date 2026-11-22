// kinject.c -- 一次性注入驱动（给 kdmapper 映射用）
//   不创建任何设备对象（kdmapper 映射的驱动一调 IoCreateDevice 就崩）
//   流程：DriverEntry -> 读 job 文件 -> PsLookupProcessByProcessId -> attach
//         -> 在目标里解析 kernel32!LoadLibraryW -> RtlCreateUserThread(LoadLibraryW, 路径)
//   日志：C:\ProgramData\kmaplog.txt
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntimage.h>

#define JOB_FILE L"\\??\\C:\\ProgramData\\kmap_job.txt"
#define LOG_FILE L"\\??\\C:\\ProgramData\\kmaplog.txt"

NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
NTSYSAPI NTSTATUS NTAPI RtlCreateUserThread(HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor,
                                            BOOLEAN CreateSuspended, ULONG StackZeroBits,
                                            SIZE_T StackReserve, SIZE_T StackCommit,
                                            PVOID StartAddress, PVOID StartParameter,
                                            PHANDLE ThreadHandle, PCLIENT_ID ClientId);

typedef ULONG64 U64;

/* ---------------- 日志 ---------------- */
static VOID KLog(PCSTR text)
{
    UNICODE_STRING path; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb; HANDLE h; size_t len = 0;
    RtlInitUnicodeString(&path, LOG_FILE);
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &iosb, NULL,
                                 FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
        return;
    RtlStringCchLengthA(text, 2048, &len);
    ZwWriteFile(h, NULL, NULL, NULL, &iosb, (PVOID)text, (ULONG)len, NULL, NULL);
    ZwFlushBuffersFile(h, &iosb);          /* 崩溃时也要留在盘上 */
    ZwClose(h);
}

static VOID KLogF(PCSTR fmt, ...)
{
    CHAR buf[1024]; va_list ap;
    va_start(ap, fmt);
    RtlStringCchVPrintfA(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    KLog(buf);
}

/* ---------------- 读 job 文件 ---------------- */
static NTSTATUS ReadJob(PUCHAR buf, ULONG cap, PULONG outLen)
{
    UNICODE_STRING path; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb; HANDLE h;
    FILE_STANDARD_INFORMATION fsi;
    LARGE_INTEGER off;
    NTSTATUS st;

    RtlInitUnicodeString(&path, JOB_FILE);
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&h, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                      FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) return st;

    st = ZwQueryInformationFile(h, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(st) || fsi.EndOfFile.QuadPart <= 0 || fsi.EndOfFile.QuadPart > cap)
    { ZwClose(h); return STATUS_INVALID_PARAMETER; }

    off.QuadPart = 0;
    st = ZwReadFile(h, NULL, NULL, NULL, &iosb, buf, (ULONG)fsi.EndOfFile.QuadPart, &off, NULL);
    ZwClose(h);
    if (!NT_SUCCESS(st)) return st;

    *outLen = (ULONG)fsi.EndOfFile.QuadPart;
    if (*outLen < cap) buf[*outLen] = 0;
    return STATUS_SUCCESS;
}

/* ---------------- 目标侧解析 ---------------- */
typedef struct _KLDR_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} KLDR_ENTRY, *PKLDR_ENTRY;

/* PEB_LDR_DATA：InLoadOrderModuleList 在 +0x10（SsHandle 之后），别当成 KLDR_ENTRY */
typedef struct _PEB_LDR
{
    ULONG      Length;
    UCHAR      Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR, *PPEB_LDR;

static PVOID TargetModuleBase(PCWSTR name)
{
    PVOID peb = PsGetProcessPeb(PsGetCurrentProcess());
    PPEB_LDR ldr;
    LIST_ENTRY* head;
    LIST_ENTRY* cur;
    PVOID result = NULL;
    UNICODE_STRING want;

    if (!peb) return NULL;
    __try
    {
        ldr = *(PPEB_LDR*)((PUCHAR)peb + 0x18);            /* PEB->Ldr */
        KLogF("[kinject] peb=%p ldr=%p\n", peb, ldr);
        if (!ldr) return NULL;
        head = &ldr->InLoadOrderModuleList;
        RtlInitUnicodeString(&want, name);
        for (cur = head->Flink; cur != head && cur; cur = cur->Flink)
        {
            PKLDR_ENTRY e = (PKLDR_ENTRY)cur;
            if (e->BaseDllName.Buffer && e->BaseDllName.Length &&
                RtlEqualUnicodeString(&e->BaseDllName, &want, TRUE))
            {
                result = e->DllBase;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { result = NULL; }
    return result;
}

static PVOID TargetGetProcAddress(PVOID modBase, PCSTR wanted)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)modBase;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_EXPORT_DIRECTORY pexp;
    ULONG* names; USHORT* ords; ULONG* funcs;
    ULONG i;

    if (!modBase || dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (PIMAGE_NT_HEADERS)((PUCHAR)modBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (!nt->OptionalHeader.DataDirectory[0].VirtualAddress) return NULL;

    pexp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)modBase + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    names = (ULONG*)((PUCHAR)modBase + pexp->AddressOfNames);
    ords  = (USHORT*)((PUCHAR)modBase + pexp->AddressOfNameOrdinals);
    funcs = (ULONG*)((PUCHAR)modBase + pexp->AddressOfFunctions);
    if (pexp->NumberOfNames > 0x10000) return NULL;

    for (i = 0; i < pexp->NumberOfNames; i++)
    {
        PCSTR a = (PCSTR)((PUCHAR)modBase + names[i]);
        PCSTR b = wanted;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0)
            return (PVOID)((PUCHAR)modBase + funcs[ords[i]]);
    }
    return NULL;
}

/* ---------------- 注入 ---------------- */
static NTSTATUS DoInject(ULONG pid, PCWSTR dllPath)
{
    PEPROCESS proc = NULL;
    KAPC_STATE apcState;
    PVOID k32, pLoad = NULL, remoteStr = NULL;
    SIZE_T strSize;
    HANDLE hThread = NULL;
    NTSTATUS st;
    UNICODE_STRING us;

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    KLogF("[kinject] pid=%lu lookup=0x%X\n", pid, st);
    if (!NT_SUCCESS(st)) return st;

    RtlInitUnicodeString(&us, dllPath);
    strSize = us.Length + sizeof(WCHAR);

    KeStackAttachProcess(proc, &apcState);
    k32 = TargetModuleBase(L"kernel32.dll");
    if (k32) pLoad = TargetGetProcAddress(k32, "LoadLibraryW");
    KLogF("[kinject] kernel32=%p LoadLibraryW=%p\n", k32, pLoad);
    KLog("[kinject] step: after module resolve\n");
    if (pLoad)
        st = ZwAllocateVirtualMemory(NtCurrentProcess(), &remoteStr, 0, &strSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    else
        st = STATUS_PROCEDURE_NOT_FOUND;

    if (NT_SUCCESS(st))
    {
        KLog("[kinject] step: alloc ok, copying path\n");
        RtlCopyMemory(remoteStr, dllPath, us.Length);
        ((PWCH)remoteStr)[us.Length / sizeof(WCHAR)] = 0;
        KLog("[kinject] step: creating user thread\n");
        st = RtlCreateUserThread((HANDLE)(LONG_PTR)-1, NULL, FALSE, 0,
                                 0x100000, 0x10000, pLoad, remoteStr, &hThread, NULL);
    }
    KeUnstackDetachProcess(&apcState);
    if (hThread) ZwClose(hThread);

    KLogF("[kinject] RtlCreateUserThread=0x%X\n", st);
    ObDereferenceObject(proc);
    return st;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UCHAR job[1024];
    ULONG len = 0;
    NTSTATUS st;
    ULONG pid = 0;
    WCHAR dll[512];
    ANSI_STRING a;
    UNICODE_STRING u;
    CHAR* nl;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    KLog("\n[kinject] === entry ===\n");
    st = ReadJob(job, sizeof(job), &len);
    KLogF("[kinject] job read=0x%X len=%lu\n", st, len);
    if (!NT_SUCCESS(st)) return st;

    /* 格式：第一行 pid，第二行 dll 完整路径 */
    nl = (CHAR*)job;
    while (*nl && *nl != '\r' && *nl != '\n') nl++;
    { CHAR pidBuf[32]; ULONG n = (ULONG)(nl - (CHAR*)job); if (n > 31) n = 31;
      RtlCopyMemory(pidBuf, job, n); pidBuf[n] = 0;
      { ULONG k = 0; pid = 0; while (pidBuf[k] >= '0' && pidBuf[k] <= '9') { pid = pid * 10 + (pidBuf[k] - '0'); k++; } } }

    while (*nl == '\r' || *nl == '\n') nl++;
    {
        CHAR pathA[512]; ULONG n = 0;
        while (nl[n] && nl[n] != '\r' && nl[n] != '\n' && n < 511) { pathA[n] = nl[n]; n++; }
        pathA[n] = 0;
        KLogF("[kinject] pid=%lu dll=%s\n", pid, pathA);
        RtlInitAnsiString(&a, pathA);
        u.Buffer = dll; u.Length = 0; u.MaximumLength = sizeof(dll);
        st = RtlAnsiStringToUnicodeString(&u, &a, FALSE);
        if (!NT_SUCCESS(st)) { KLogF("[kinject] path conv=0x%X\n", st); return st; }
    }

    st = DoInject(pid, dll);
    KLogF("[kinject] done=0x%X\n", st);
    return st;
}

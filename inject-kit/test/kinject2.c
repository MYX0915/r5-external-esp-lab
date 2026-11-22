// kinject2.c -- 驻留等待型注入驱动（kdmapper 映射）
//   DriverEntry: 起系统线程；线程按进程名轮询（ZwQuerySystemInformation）
//   找到目标 -> 等 SettleSec -> 零句柄注入（LoadLibraryW 远程线程）
//   全程不创建设备对象；日志 C:\ProgramData\kmaplog.txt
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
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG Class, PVOID Buffer, ULONG Length, PULONG ReturnLength);

typedef struct _SPI_HEAD
{
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  WorkingSetPrivateSize;
    ULONG          HardFaultCount;
    ULONG          NumberOfThreadsHighWatermark;
    ULONGLONG      CycleTime;
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
} SPI_HEAD, *PSPI_HEAD;

static ULONG g_settleSec = 25;

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
    ZwFlushBuffersFile(h, &iosb);
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

/* 按镜像名找 pid；返回 0 表示没找到 */
static ULONG FindPidByName(PCWSTR imageName)
{
    ULONG  size = 1 << 20;
    PVOID  buf = NULL;
    ULONG  ret = 0;
    NTSTATUS st;
    UNICODE_STRING want;

    buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'pmiK');
    if (!buf) return 0;
    st = ZwQuerySystemInformation(5 /*SystemProcessInformation*/, buf, size, &ret);
    if (st == STATUS_INFO_LENGTH_MISMATCH && ret > size)
    {
        ExFreePoolWithTag(buf, 'pmiK');
        size = ret + 0x1000;
        buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'pmiK');
        if (!buf) return 0;
        st = ZwQuerySystemInformation(5, buf, size, &ret);
    }
    if (!NT_SUCCESS(st)) { ExFreePoolWithTag(buf, 'pmiK'); return 0; }

    RtlInitUnicodeString(&want, imageName);
    {
        PUCHAR p = (PUCHAR)buf;
        for (;;)
        {
            PSPI_HEAD e = (PSPI_HEAD)p;
            if (e->ImageName.Buffer && e->ImageName.Length)
            {
                UNICODE_STRING u;
                u.Buffer = e->ImageName.Buffer;
                u.Length = e->ImageName.Length;
                u.MaximumLength = e->ImageName.Length;
                if (RtlEqualUnicodeString(&u, &want, TRUE))
                {
                    ExFreePoolWithTag(buf, 'pmiK');
                    return (ULONG)(ULONG_PTR)e->UniqueProcessId;
                }
            }
            if (!e->NextEntryOffset) break;
            p += e->NextEntryOffset;
        }
    }
    ExFreePoolWithTag(buf, 'pmiK');
    return 0;
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
        ldr = *(PPEB_LDR*)((PUCHAR)peb + 0x18);
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
    KLogF("[kinject2] pid=%lu lookup=0x%X\n", pid, st);
    if (!NT_SUCCESS(st)) return st;

    RtlInitUnicodeString(&us, dllPath);
    strSize = us.Length + sizeof(WCHAR);

    KeStackAttachProcess(proc, &apcState);
    k32 = TargetModuleBase(L"kernel32.dll");
    if (k32) pLoad = TargetGetProcAddress(k32, "LoadLibraryW");
    KLogF("[kinject2] kernel32=%p LoadLibraryW=%p\n", k32, pLoad);
    if (pLoad)
        st = ZwAllocateVirtualMemory(NtCurrentProcess(), &remoteStr, 0, &strSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    else
        st = STATUS_PROCEDURE_NOT_FOUND;

    if (NT_SUCCESS(st))
    {
        RtlCopyMemory(remoteStr, dllPath, us.Length);
        ((PWCH)remoteStr)[us.Length / sizeof(WCHAR)] = 0;
        st = RtlCreateUserThread((HANDLE)(LONG_PTR)-1, NULL, FALSE, 0,
                                 0x100000, 0x10000, pLoad, remoteStr, &hThread, NULL);
    }
    KeUnstackDetachProcess(&apcState);
    if (hThread) ZwClose(hThread);

    KLogF("[kinject2] RtlCreateUserThread=0x%X\n", st);
    ObDereferenceObject(proc);
    return st;
}

typedef struct _JOB
{
    WCHAR ImageName[128];
    WCHAR DllPath[512];
} JOB, *PJOB;

static VOID WaiterThread(PVOID ctx)
{
    JOB* job = (JOB*)ctx;
    LARGE_INTEGER delay;
    ULONG waited = 0;
    ULONG pid = 0;

    KLog("[kinject2] waiter thread alive\n");
    {
        CHAR nm[256] = {0}; int i = 0;
        while (job->ImageName[i] && i < 127) { nm[i] = (CHAR)job->ImageName[i]; i++; }
        KLogF("[kinject2] target image = %s\n", nm);
    }

    for (;;)
    {
        pid = FindPidByName(job->ImageName);
        if (pid) { KLogF("[kinject2] found %ls pid=%lu\n", job->ImageName, pid); break; }
        delay.QuadPart = -5000000LL;                 /* 0.5s */
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
        waited += 500;
        if (waited > 1800000) { KLog("[kinject2] timeout waiting (30min)\n"); PsTerminateSystemThread(STATUS_TIMEOUT); }
    }

    {
        LARGE_INTEGER settle;
        settle.QuadPart = -(LONGLONG)g_settleSec * 10000000LL;
        KLogF("[kinject2] settling %lu s\n", g_settleSec);
        KeDelayExecutionThread(KernelMode, FALSE, &settle);
        KLogF("[kinject2] injecting into %lu\n", pid);
        DoInject(pid, job->DllPath);
        KLog("[kinject2] done\n");
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static BOOLEAN ParseJob(PJOB job)
{
    UNICODE_STRING path; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb; HANDLE h;
    FILE_STANDARD_INFORMATION fsi;
    UCHAR buf[2048];
    LARGE_INTEGER off;
    NTSTATUS st;
    CHAR* p;
    CHAR* nl;
    ANSI_STRING a;
    UNICODE_STRING u;

    RtlInitUnicodeString(&path, JOB_FILE);
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&h, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                      FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) return FALSE;
    st = ZwQueryInformationFile(h, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(st) || fsi.EndOfFile.QuadPart <= 0 || fsi.EndOfFile.QuadPart >= (LONGLONG)sizeof(buf))
    { ZwClose(h); return FALSE; }
    off.QuadPart = 0;
    st = ZwReadFile(h, NULL, NULL, NULL, &iosb, buf, (ULONG)fsi.EndOfFile.QuadPart, &off, NULL);
    ZwClose(h);
    if (!NT_SUCCESS(st)) return FALSE;
    buf[fsi.EndOfFile.QuadPart] = 0;

    p = (CHAR*)buf;
    nl = p; while (*nl && *nl != '\r' && *nl != '\n') nl++;
    {
        CHAR nameA[128]; ULONG n = (ULONG)(nl - p); if (n > 127) n = 127;
        RtlCopyMemory(nameA, p, n); nameA[n] = 0;
        RtlInitAnsiString(&a, nameA);
        u.Buffer = job->ImageName; u.Length = 0; u.MaximumLength = sizeof(job->ImageName);
        if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&u, &a, FALSE))) return FALSE;
    }
    while (*nl == '\r' || *nl == '\n') nl++;
    {
        CHAR pathA[512]; ULONG n = 0;
        while (nl[n] && nl[n] != '\r' && nl[n] != '\n' && n < 511) { pathA[n] = nl[n]; n++; }
        pathA[n] = 0;
        RtlInitAnsiString(&a, pathA);
        u.Buffer = job->DllPath; u.Length = 0; u.MaximumLength = sizeof(job->DllPath);
        if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&u, &a, FALSE))) return FALSE;
    }
    return TRUE;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    static JOB job;
    HANDLE h = NULL;
    NTSTATUS st;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    KLog("\n[kinject2] === entry ===\n");
    RtlZeroMemory(&job, sizeof(job));
    if (!ParseJob(&job)) { KLog("[kinject2] job parse failed\n"); return STATUS_INVALID_PARAMETER; }
    { CHAR nm[256] = {0}, dp[600] = {0}; int i = 0;
      while (job.ImageName[i] && i < 127) { nm[i] = (CHAR)job.ImageName[i]; i++; }
      i = 0; while (job.DllPath[i] && i < 511) { dp[i] = (CHAR)job.DllPath[i]; i++; }
      KLogF("[kinject2] job: target=%s dll=%s\n", nm, dp); }

    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, WaiterThread, &job);
    if (NT_SUCCESS(st) && h) ZwClose(h);
    KLogF("[kinject2] thread=0x%X\n", st);
    {   /* 诊断：给线程 3 秒，看它有没有机会跑 */
        LARGE_INTEGER d; d.QuadPart = -30000000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &d);
        KLog("[kinject2] entry still alive after 3s\n");
    }
    return STATUS_SUCCESS;
}

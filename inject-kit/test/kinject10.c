// kinject10.c -- 驻留等待 + 注入 + 结果回读（诊断 Apex 里 LoadLibraryW 的真实返回）
//   等待线程按镜像名轮询 -> 找到后 settle -> attach 注入 shellcode:
//       LoadLibraryW(path) -> [res] = rax ; GetLastError() -> [res+8] = eax
//   -> 3s 后回读 res，并检查 payload.dll 是否进 PEB->Ldr
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntimage.h>

#define JOB_FILE L"\\??\\C:\\ProgramData\\kmap_job.txt"
#define LOG_FILE L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define SETTLE_SEC 25

NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
NTSYSAPI NTSTATUS NTAPI RtlCreateUserThread(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG,
                                            SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PCLIENT_ID);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG Class, PVOID Buffer, ULONG Length, PULONG ReturnLength);
NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
                                               PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

typedef struct _SPI_HEAD
{
    ULONG NextEntryOffset; ULONG NumberOfThreads; LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount; ULONG NumberOfThreadsHighWatermark; ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime, UserTime, KernelTime; UNICODE_STRING ImageName;
    LONG BasePriority; HANDLE UniqueProcessId;
} SPI_HEAD, *PSPI_HEAD;

typedef struct _KLDR_ENTRY
{
    LIST_ENTRY InLoadOrderLinks, InMemoryOrderLinks, InInitializationOrderLinks;
    PVOID DllBase, EntryPoint; ULONG SizeOfImage; UNICODE_STRING FullDllName, BaseDllName;
} KLDR_ENTRY, *PKLDR_ENTRY;

typedef struct _PEB_LDR { ULONG Length; UCHAR Initialized; PVOID SsHandle; LIST_ENTRY InLoadOrderModuleList; } PEB_LDR, *PPEB_LDR;

static VOID KLog(PCSTR t)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h; size_t n = 0;
    RtlInitUnicodeString(&p, LOG_FILE);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &io, NULL,
                                 FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0))) return;
    RtlStringCchLengthA(t, 2048, &n);
    ZwWriteFile(h, NULL, NULL, NULL, &io, (PVOID)t, (ULONG)n, NULL, NULL);
    ZwFlushBuffersFile(h, &io); ZwClose(h);
}
static VOID KLogF(PCSTR f, ...)
{ CHAR b[1024]; va_list ap; va_start(ap, f); RtlStringCchVPrintfA(b, sizeof(b), f, ap); va_end(ap); KLog(b); }

static ULONG FindPidByName2(PCWSTR imageName, LARGE_INTEGER* outCreate, ULONG* outThreads)
{
    ULONG size = 1 << 20, ret = 0; PVOID buf; NTSTATUS st; UNICODE_STRING want;
    buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'pmiK');
    if (!buf) return 0;
    st = ZwQuerySystemInformation(5, buf, size, &ret);
    if (st == STATUS_INFO_LENGTH_MISMATCH && ret > size)
    { ExFreePoolWithTag(buf, 'pmiK'); size = ret + 0x1000; buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'pmiK'); if (!buf) return 0; st = ZwQuerySystemInformation(5, buf, size, &ret); }
    if (!NT_SUCCESS(st)) { ExFreePoolWithTag(buf, 'pmiK'); return 0; }
    RtlInitUnicodeString(&want, imageName);
    { PUCHAR p = (PUCHAR)buf;
      for (;;) {
        PSPI_HEAD e = (PSPI_HEAD)p;
        if (e->ImageName.Buffer && e->ImageName.Length) {
            UNICODE_STRING u; u.Buffer = e->ImageName.Buffer; u.Length = e->ImageName.Length; u.MaximumLength = e->ImageName.Length;
            if (RtlEqualUnicodeString(&u, &want, TRUE)) { if (outCreate) *outCreate = e->CreateTime; if (outThreads) *outThreads = e->NumberOfThreads; ExFreePoolWithTag(buf, 'pmiK'); return (ULONG)(ULONG_PTR)e->UniqueProcessId; }
        }
        if (!e->NextEntryOffset) break;
        p += e->NextEntryOffset;
      } }
    ExFreePoolWithTag(buf, 'pmiK');
    return 0;
}

static PVOID TargetModuleBase(PCWSTR name)
{
    PVOID peb = PsGetProcessPeb(PsGetCurrentProcess()); PPEB_LDR ldr; LIST_ENTRY *head, *cur;
    PVOID r = NULL; UNICODE_STRING w;
    if (!peb) return NULL;
    {
        ldr = *(PPEB_LDR*)((PUCHAR)peb + 0x18);
        if (!ldr) return NULL;
        head = &ldr->InLoadOrderModuleList; RtlInitUnicodeString(&w, name);
        for (cur = head->Flink; cur != head && cur; cur = cur->Flink) {
            PKLDR_ENTRY e = (PKLDR_ENTRY)cur;
            if (e->BaseDllName.Buffer && e->BaseDllName.Length && RtlEqualUnicodeString(&e->BaseDllName, &w, TRUE)) { r = e->DllBase; break; }
        }
    }
    return r;
}

static PVOID TargetGetProcAddress(PVOID m, PCSTR wanted)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)m; PIMAGE_NT_HEADERS nt; PIMAGE_EXPORT_DIRECTORY pe;
    ULONG *names, *funcs; USHORT* ords; ULONG i;
    if (!m || dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (PIMAGE_NT_HEADERS)((PUCHAR)m + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || !nt->OptionalHeader.DataDirectory[0].VirtualAddress) return NULL;
    pe = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)m + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    names = (ULONG*)((PUCHAR)m + pe->AddressOfNames); ords = (USHORT*)((PUCHAR)m + pe->AddressOfNameOrdinals);
    funcs = (ULONG*)((PUCHAR)m + pe->AddressOfFunctions);
    if (pe->NumberOfNames > 0x10000) return NULL;
    for (i = 0; i < pe->NumberOfNames; i++) {
        PCSTR a = (PCSTR)((PUCHAR)m + names[i]); PCSTR b = wanted;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0) return (PVOID)((PUCHAR)m + funcs[ords[i]]);
    }
    return NULL;
}

static NTSTATUS InjectAndCapture(ULONG pid, PCWSTR dllPath)
{
    PEPROCESS proc = NULL; KAPC_STATE apc; PVOID k32 = NULL, pLoad = NULL, pGle = NULL;
    PVOID pathVa = NULL, shellVa = NULL, resVa = NULL;
    SIZE_T pathSize, shellSize = 0x1000, resSize = 0x10;
    UCHAR code[96]; ULONG n = 0; HANDLE th = NULL; NTSTATUS st; UNICODE_STRING us;
    ULONG64 ret = 0, err = 0; BOOLEAN inLdr = FALSE;

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    KLogF("[kinject10] lookup pid=%lu = 0x%X\n", pid, st);
    if (!NT_SUCCESS(st)) return st;

    RtlInitUnicodeString(&us, dllPath);
    pathSize = us.Length + sizeof(WCHAR);

    KeStackAttachProcess(proc, &apc);
    KLogF("[kinject10] attached, curpid=%lu wantpid=%lu\n",
          (ULONG)(ULONG_PTR)PsGetProcessId(PsGetCurrentProcess()), pid);
    k32 = TargetModuleBase(L"kernel32.dll");
    if (k32) { pLoad = TargetGetProcAddress(k32, "LoadLibraryW"); pGle = TargetGetProcAddress(k32, "GetLastError"); }
    KLogF("[kinject10] kernel32=%p LoadLibraryW=%p GetLastError=%p\n", k32, pLoad, pGle);
    if (!pLoad) { KeUnstackDetachProcess(&apc); ObDereferenceObject(proc); return STATUS_PROCEDURE_NOT_FOUND; }

    st = ZwAllocateVirtualMemory(NtCurrentProcess(), &pathVa, 0, &pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    KLogF("[kinject10] alloc path st=0x%X va=%p\n", st, pathVa);
    if (NT_SUCCESS(st)) {
        st = ZwAllocateVirtualMemory(NtCurrentProcess(), &resVa, 0, &resSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        KLogF("[kinject10] alloc res st=0x%X va=%p\n", st, resVa);
    }
    if (NT_SUCCESS(st)) {
        st = ZwAllocateVirtualMemory(NtCurrentProcess(), &shellVa, 0, &shellSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        KLogF("[kinject10] alloc shell(RW) st=0x%X va=%p\n", st, shellVa);
    }

    if (NT_SUCCESS(st))
    {
        RtlCopyMemory(pathVa, dllPath, us.Length);
        *(PWCH)((PUCHAR)pathVa + us.Length) = 0;
        *(ULONG64*)resVa = 0; *(ULONG64*)((PUCHAR)resVa + 8) = 0;

        /* sub rsp,0x28; mov rcx,path; mov rax,LoadLibraryW; call rax;
           mov rbx,rax; mov rdx,res; mov [rdx],rax;
           mov rax,GetLastError; call rax; mov [rdx+8],eax; add rsp,0x28; ret */
        code[n++]=0x48; code[n++]=0x83; code[n++]=0xEC; code[n++]=0x28;
        code[n++]=0x48; code[n++]=0xB9; *(ULONG64*)(code+n)=(ULONG64)pathVa; n+=8;
        code[n++]=0x48; code[n++]=0xB8; *(ULONG64*)(code+n)=(ULONG64)pLoad; n+=8;
        code[n++]=0xFF; code[n++]=0xD0;
        code[n++]=0x48; code[n++]=0x89; code[n++]=0xC3;
        code[n++]=0x48; code[n++]=0xBA; *(ULONG64*)(code+n)=(ULONG64)resVa; n+=8;
        code[n++]=0x48; code[n++]=0x89; code[n++]=0x02;
        if (pGle) {
            code[n++]=0x48; code[n++]=0xB8; *(ULONG64*)(code+n)=(ULONG64)pGle; n+=8;
            code[n++]=0xFF; code[n++]=0xD0;
            code[n++]=0x89; code[n++]=0x42; code[n++]=0x08;
        }
        code[n++]=0x48; code[n++]=0x83; code[n++]=0xC4; code[n++]=0x28;
        code[n++]=0xC3;
        RtlCopyMemory(shellVa, code, n);
        {
            PVOID b = shellVa; SIZE_T r = shellSize; ULONG oldp = 0;
            NTSTATUS pst = ZwProtectVirtualMemory(NtCurrentProcess(), &b, &r, PAGE_EXECUTE_READ, &oldp);
            KLogF("[kinject10] protect RX st=0x%X\n", pst);
            if (!NT_SUCCESS(pst))
            {
                KLog("[kinject10] exec page blocked -> fallback: thread at LoadLibraryW");
                st = RtlCreateUserThread((HANDLE)(LONG_PTR)-1, NULL, FALSE, 0, 0x100000, 0x10000,
                                         pLoad, pathVa, &th, NULL);
                KLogF("[kinject10] thread(fallback)=0x%X\n", st);
                shellVa = NULL;
            }
        }
        if (shellVa)
        {
            st = RtlCreateUserThread((HANDLE)(LONG_PTR)-1, NULL, FALSE, 0, 0x100000, 0x10000, shellVa, NULL, &th, NULL);
            KLogF("[kinject10] thread=0x%X\n", st);
        }
    }
    KeUnstackDetachProcess(&apc);
    if (th) ZwClose(th);
    if (!NT_SUCCESS(st)) { ObDereferenceObject(proc); return st; }

    { LARGE_INTEGER d; d.QuadPart = -30000000LL; KeDelayExecutionThread(KernelMode, FALSE, &d); }

    KeStackAttachProcess(proc, &apc);
    {
        if (shellVa) { ret = *(ULONG64*)resVa; err = *(ULONG64*)((PUCHAR)resVa + 8); }
        inLdr = (TargetModuleBase(L"payload.dll") != NULL);
    }
    KeUnstackDetachProcess(&apc);

    KLogF("[kinject10] LoadLibraryW=0x%llX GetLastError=0x%llX inLdr=%d\n", ret, err, (int)inLdr);

    /* === 线程执行能力测试：start = kernel32!Sleep，参数 8000ms === */
    {
        PVOID pSleep = NULL; HANDLE th2 = NULL; ULONG t0 = 0, t1 = 0, t2 = 0;
        LARGE_INTEGER ct;
        KeStackAttachProcess(proc, &apc);
        if (k32) pSleep = TargetGetProcAddress(k32, "Sleep");
        KLogF("[kinject10] Sleep=%p\n", pSleep);
        if (pSleep)
            st = RtlCreateUserThread((HANDLE)(LONG_PTR)-1, NULL, FALSE, 0, 0x100000, 0x10000,
                                     pSleep, (PVOID)8000, &th2, NULL);
        KeUnstackDetachProcess(&apc);
        if (th2) ZwClose(th2);
        KLogF("[kinject10] sleep-thread st=0x%X\n", st);

        FindPidByName2(L"r5apex_dx12.exe", &ct, &t0);
        { LARGE_INTEGER d; d.QuadPart = -10000000LL; KeDelayExecutionThread(KernelMode, FALSE, &d); }
        FindPidByName2(L"r5apex_dx12.exe", &ct, &t1);
        { LARGE_INTEGER d; d.QuadPart = -100000000LL; KeDelayExecutionThread(KernelMode, FALSE, &d); }
        FindPidByName2(L"r5apex_dx12.exe", &ct, &t2);
        KLogF("[kinject10] threads: after=%lu +1s=%lu +11s=%lu\n", t0, t1, t2);
    }

    ObDereferenceObject(proc);
    return STATUS_SUCCESS;
}

static BOOLEAN ParseJob(WCHAR* image, WCHAR* dll)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    FILE_STANDARD_INFORMATION fsi; UCHAR buf[2048]; LARGE_INTEGER off; NTSTATUS st; CHAR *s, *nl; ULONG i = 0;

    RtlInitUnicodeString(&p, JOB_FILE);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&h, GENERIC_READ | SYNCHRONIZE, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) return FALSE;
    st = ZwQueryInformationFile(h, &io, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(st) || fsi.EndOfFile.QuadPart <= 0 || fsi.EndOfFile.QuadPart >= (LONGLONG)sizeof(buf)) { ZwClose(h); return FALSE; }
    off.QuadPart = 0;
    st = ZwReadFile(h, NULL, NULL, NULL, &io, buf, (ULONG)fsi.EndOfFile.QuadPart, &off, NULL);
    ZwClose(h);
    if (!NT_SUCCESS(st)) return FALSE;
    buf[fsi.EndOfFile.QuadPart] = 0;

    s = (CHAR*)buf;
    while (*s && *s != '\r' && *s != '\n' && i < 127) { image[i++] = (WCHAR)*s++; }
    image[i] = 0;
    nl = s; while (*nl && *nl != '\r' && *nl != '\n') nl++;
    s = nl; while (*s == '\r' || *s == '\n') s++;
    i = 0;
    while (*s && *s != '\r' && *s != '\n' && i < 511) { dll[i++] = (WCHAR)*s++; }
    dll[i] = 0;
    return (i > 0);
}

static VOID WaiterThread(PVOID ctx)
{
    WCHAR* dll = (WCHAR*)ctx;
    LARGE_INTEGER dl, ct, ctNow;
    ULONG waited = 0, pid = 0, stableMs = 0, lastPid = 0;

    ct.QuadPart = 0;
    KLog("[kinject10] waiter alive\n");
    for (;;)
    {
        pid = FindPidByName2(L"r5apex_dx12.exe", &ctNow, NULL);
        if (pid && pid == lastPid && ctNow.QuadPart == ct.QuadPart) { stableMs += 500; }
        else { lastPid = pid; ct = ctNow; stableMs = 0; if (pid) KLogF("[kinject10] target pid=%lu timer reset\n", pid); }

        if (pid && stableMs >= (ULONG)SETTLE_SEC * 1000)
        {
            KLogF("[kinject10] pid=%lu stable %lu ms -> inject\n", pid, stableMs);
            InjectAndCapture(pid, dll);
            KLog("[kinject10] done\n");
            PsTerminateSystemThread(STATUS_SUCCESS);
        }

        dl.QuadPart = -5000000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &dl);
        waited += 500;
        if (waited > 3600000) { KLog("[kinject10] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); }
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    static WCHAR dll[512];
    static WCHAR image[128];
    HANDLE h = NULL; NTSTATUS st;

    UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    KLog("\n[kinject10] === entry ===\n");
    RtlZeroMemory(image, sizeof(image)); RtlZeroMemory(dll, sizeof(dll));
    if (!ParseJob(image, dll)) { KLog("[kinject10] job parse failed\n"); return STATUS_INVALID_PARAMETER; }
    KLog("[kinject10] job parsed\n");

    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, WaiterThread, dll);
    if (NT_SUCCESS(st) && h) ZwClose(h);
    KLogF("[kinject10] thread=0x%X\n", st);
    { LARGE_INTEGER d; d.QuadPart = -30000000LL; KeDelayExecutionThread(KernelMode, FALSE, &d); }
    return STATUS_SUCCESS;
}

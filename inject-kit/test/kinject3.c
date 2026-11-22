// kinject3.c -- 一次性注入 + 结果回写（诊断 Apex 里 LoadLibraryW 到底成不成功）
//   shellcode: LoadLibraryW(path) -> 把返回值写到 result 槽
//   随后 attach 读回 result，并枚举目标模块看 dll 有没有进 PEB->Ldr
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntimage.h>

#define JOB_FILE L"\\??\\C:\\ProgramData\\kmap_job.txt"
#define LOG_FILE L"\\??\\C:\\ProgramData\\kmaplog.txt"

NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
NTSYSAPI NTSTATUS NTAPI RtlCreateUserThread(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG,
                                            SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PCLIENT_ID);

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
    ULONG Length; UCHAR Initialized; PVOID SsHandle; LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR, *PPEB_LDR;

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
    ZwFlushBuffersFile(h, &io);
    ZwClose(h);
}

static VOID KLogF(PCSTR f, ...)
{
    CHAR b[1024]; va_list ap; va_start(ap, f);
    RtlStringCchVPrintfA(b, sizeof(b), f, ap); va_end(ap); KLog(b);
}

static PVOID TargetModuleBase(PCWSTR name)
{
    PVOID peb = PsGetProcessPeb(PsGetCurrentProcess());
    PPEB_LDR ldr; LIST_ENTRY* head; LIST_ENTRY* cur; PVOID r = NULL; UNICODE_STRING w;
    if (!peb) return NULL;
    __try
    {
        ldr = *(PPEB_LDR*)((PUCHAR)peb + 0x18);
        if (!ldr) return NULL;
        head = &ldr->InLoadOrderModuleList;
        RtlInitUnicodeString(&w, name);
        for (cur = head->Flink; cur != head && cur; cur = cur->Flink)
        {
            PKLDR_ENTRY e = (PKLDR_ENTRY)cur;
            if (e->BaseDllName.Buffer && e->BaseDllName.Length &&
                RtlEqualUnicodeString(&e->BaseDllName, &w, TRUE)) { r = e->DllBase; break; }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { r = NULL; }
    return r;
}

static PVOID TargetGetProcAddress(PVOID m, PCSTR wanted)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)m; PIMAGE_NT_HEADERS nt; PIMAGE_EXPORT_DIRECTORY pe;
    ULONG *names, *funcs; USHORT* ords; ULONG i;
    if (!m || dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (PIMAGE_NT_HEADERS)((PUCHAR)m + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (!nt->OptionalHeader.DataDirectory[0].VirtualAddress) return NULL;
    pe = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)m + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    names = (ULONG*)((PUCHAR)m + pe->AddressOfNames);
    ords = (USHORT*)((PUCHAR)m + pe->AddressOfNameOrdinals);
    funcs = (ULONG*)((PUCHAR)m + pe->AddressOfFunctions);
    if (pe->NumberOfNames > 0x10000) return NULL;
    for (i = 0; i < pe->NumberOfNames; i++)
    {
        PCSTR a = (PCSTR)((PUCHAR)m + names[i]); PCSTR b = wanted;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0) return (PVOID)((PUCHAR)m + funcs[ords[i]]);
    }
    return NULL;
}

/* 在目标里执行：LoadLibraryW(path) 并把返回值写到 result */
static NTSTATUS InjectAndCapture(PEPROCESS proc, PCWSTR dllPath, ULONG64* outRet, BOOLEAN* outInLdr)
{
    KAPC_STATE apc;
    PVOID k32, pLoad = NULL, pathVa = NULL, shellVa = NULL, resVa = NULL;
    SIZE_T pathSize, shellSize = 0x1000, resSize = 8;
    UCHAR code[64]; ULONG n = 0;
    HANDLE th = NULL;
    NTSTATUS st;
    UNICODE_STRING us;

    *outRet = 0; *outInLdr = FALSE;

    RtlInitUnicodeString(&us, dllPath);
    pathSize = us.Length + sizeof(WCHAR);

    KeStackAttachProcess(proc, &apc);
    k32 = TargetModuleBase(L"kernel32.dll");
    if (k32) pLoad = TargetGetProcAddress(k32, "LoadLibraryW");
    KLogF("[kinject3] kernel32=%p LoadLibraryW=%p\n", k32, pLoad);

    if (!pLoad) { KeUnstackDetachProcess(&apc); return STATUS_PROCEDURE_NOT_FOUND; }

    st = ZwAllocateVirtualMemory(NtCurrentProcess(), &pathVa, 0, &pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (NT_SUCCESS(st))
        st = ZwAllocateVirtualMemory(NtCurrentProcess(), &resVa, 0, &resSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (NT_SUCCESS(st))
        st = ZwAllocateVirtualMemory(NtCurrentProcess(), &shellVa, 0, &shellSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (NT_SUCCESS(st))
    {
        RtlCopyMemory(pathVa, dllPath, us.Length);
        *(PWCH)((PUCHAR)pathVa + us.Length) = 0;
        *(ULONG64*)resVa = 0;

        /* 48 83 EC 28 | 48 B9 <path> | 48 B8 <LoadLibraryW> | FF D0
           | 48 BA <result> | 48 89 02 | 48 83 C4 28 | C3 */
        code[n++] = 0x48; code[n++] = 0x83; code[n++] = 0xEC; code[n++] = 0x28;
        code[n++] = 0x48; code[n++] = 0xB9; *(ULONG64*)(code + n) = (ULONG64)pathVa; n += 8;
        code[n++] = 0x48; code[n++] = 0xB8; *(ULONG64*)(code + n) = (ULONG64)pLoad; n += 8;
        code[n++] = 0xFF; code[n++] = 0xD0;
        code[n++] = 0x48; code[n++] = 0xBA; *(ULONG64*)(code + n) = (ULONG64)resVa; n += 8;
        code[n++] = 0x48; code[n++] = 0x89; code[n++] = 0x02;
        code[n++] = 0x48; code[n++] = 0x83; code[n++] = 0xC4; code[n++] = 0x28;
        code[n++] = 0xC3;
        RtlCopyMemory(shellVa, code, n);

        st = RtlCreateUserThread((HANDLE)(LONG_PTR)-1, NULL, FALSE, 0, 0x100000, 0x10000,
                                 shellVa, NULL, &th, NULL);
        KLogF("[kinject3] thread=0x%X\n", st);
    }
    KeUnstackDetachProcess(&apc);
    if (th) ZwClose(th);
    if (!NT_SUCCESS(st)) return st;

    { LARGE_INTEGER d; d.QuadPart = -30000000LL; KeDelayExecutionThread(KernelMode, FALSE, &d); }  /* 3s */

    KeStackAttachProcess(proc, &apc);
    __try
    {
        *outRet = *(ULONG64*)resVa;
        { PVOID pm = TargetModuleBase(L"payload.dll"); *outInLdr = (pm != NULL); }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
    KeUnstackDetachProcess(&apc);

    KLogF("[kinject3] LoadLibraryW returned 0x%llX  inLdr=%d\n", *outRet, (int)*outInLdr);
    return STATUS_SUCCESS;
}

static BOOLEAN ParseJob(ULONG* pid, WCHAR* dll, ULONG dllChars)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    FILE_STANDARD_INFORMATION fsi; UCHAR buf[2048]; LARGE_INTEGER off; NTSTATUS st;
    CHAR* s; CHAR* nl; ULONG v = 0; ULONG i = 0;

    RtlInitUnicodeString(&p, JOB_FILE);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&h, GENERIC_READ | SYNCHRONIZE, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) return FALSE;
    st = ZwQueryInformationFile(h, &io, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(st) || fsi.EndOfFile.QuadPart <= 0 || fsi.EndOfFile.QuadPart >= (LONGLONG)sizeof(buf))
    { ZwClose(h); return FALSE; }
    off.QuadPart = 0;
    st = ZwReadFile(h, NULL, NULL, NULL, &io, buf, (ULONG)fsi.EndOfFile.QuadPart, &off, NULL);
    ZwClose(h);
    if (!NT_SUCCESS(st)) return FALSE;
    buf[fsi.EndOfFile.QuadPart] = 0;

    s = (CHAR*)buf;
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    *pid = v;
    while (*s && *s != '\r' && *s != '\n') s++;
    while (*s == '\r' || *s == '\n') s++;
    while (*s && *s != '\r' && *s != '\n' && i < dllChars - 1) { dll[i++] = (WCHAR)*s++; }
    dll[i] = 0;
    return (v != 0 && i > 0);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    static WCHAR dll[512];
    ULONG pid = 0;
    NTSTATUS st;
    ULONG64 ret = 0; BOOLEAN inLdr = FALSE;
    PEPROCESS proc = NULL;

    UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    KLog("\n[kinject3] === entry ===\n");

    if (!ParseJob(&pid, dll, 512)) { KLog("[kinject3] job parse failed\n"); return STATUS_INVALID_PARAMETER; }
    KLogF("[kinject3] pid=%lu\n", pid);

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    KLogF("[kinject3] lookup=0x%X\n", st);
    if (!NT_SUCCESS(st)) return st;

    st = InjectAndCapture(proc, dll, &ret, &inLdr);
    KLogF("[kinject3] inject=0x%X ret=0x%llX inLdr=%d\n", st, ret, (int)inLdr);
    ObDereferenceObject(proc);
    return st;
}

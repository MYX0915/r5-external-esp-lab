// unhook3.sys -- 用 MmPteBase 自映射直接改 PTE 来还原 inline hook
#include <ntifs.h>
#include <ntstrsafe.h>

#define LOG_FILE   L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define SETTLE_SEC 20
#define PTE_BASE   0xFFFFF58000000000ULL

NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

typedef struct _SPI9 { ULONG Next; ULONG Threads; LARGE_INTEGER W; ULONG HF; ULONG HW;
    ULONGLONG CT; LARGE_INTEGER Cr; LARGE_INTEGER U; LARGE_INTEGER K;
    UNICODE_STRING ImageName; LONG BP; HANDLE PID; } SPI9, *PSPI9;

typedef struct _PATCH { PCWSTR Dll; PCSTR Api; ULONG Rva; UCHAR Orig[8]; } PATCH;

static const PATCH g_patches[] = {
    { L"ntdll.dll",    "NtAllocateVirtualMemory", 0x1666D0, { 0x4C,0x8B,0xD1,0xB8,0x18,0x00,0x00,0x00 } },
    { L"ntdll.dll",    "NtProtectVirtualMemory",  0x166DD0, { 0x4C,0x8B,0xD1,0xB8,0x50,0x00,0x00,0x00 } },
    { L"ntdll.dll",    "NtMapViewOfSection",      0x1668D0, { 0x4C,0x8B,0xD1,0xB8,0x28,0x00,0x00,0x00 } },
    { L"ntdll.dll",    "LdrLoadDll",              0x03E550, { 0x4C,0x8B,0xDC,0x49,0x89,0x5B,0x10,0x56 } },
    { L"kernel32.dll", "LoadLibraryW",            0x03F6C0, { 0x48,0xFF,0x25,0x21,0xBD,0x04,0x00,0xCC } },
    { L"kernel32.dll", "LoadLibraryExW",          0x03C7B0, { 0x48,0xFF,0x25,0xF1,0xEB,0x04,0x00,0xCC } },
    { L"kernel32.dll", "VirtualAlloc",            0x033160, { 0x48,0xFF,0x25,0x11,0x85,0x05,0x00,0xCC } },
    { L"kernel32.dll", "VirtualProtect",          0x038460, { 0x48,0xFF,0x25,0x29,0x32,0x05,0x00,0xCC } },
};

static VOID WriteA(PCWSTR file, PCSTR text, ULONG len)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    RtlInitUnicodeString(&p, file);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &io, NULL,
                                 FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0))) return;
    ZwWriteFile(h, NULL, NULL, NULL, &io, (PVOID)text, len, NULL, NULL);
    ZwFlushBuffersFile(h, &io); ZwClose(h);
}
static VOID KLog(PCSTR t) { size_t n = 0; RtlStringCchLengthA(t, 2048, &n); WriteA(LOG_FILE, t, (ULONG)n); }
static VOID KLogF(PCSTR f, ...) { CHAR b[400]; va_list ap; va_start(ap, f); RtlStringCchVPrintfA(b, sizeof(b), f, ap); va_end(ap); KLog(b); }

static ULONG FindPid(PCWSTR name, LARGE_INTEGER* outCreate)
{
    ULONG size = 1 << 20, ret = 0, result = 0;
    PVOID buf; NTSTATUS st; UNICODE_STRING want;
    buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'pmiK');
    if (buf == NULL) return 0;
    st = ZwQuerySystemInformation(5, buf, size, &ret);
    if (st == STATUS_INFO_LENGTH_MISMATCH && ret > size) {
        ExFreePoolWithTag(buf, 'pmiK'); size = ret + 0x1000;
        buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'pmiK');
        if (buf == NULL) return 0;
        st = ZwQuerySystemInformation(5, buf, size, &ret);
    }
    if (!NT_SUCCESS(st)) { ExFreePoolWithTag(buf, 'pmiK'); return 0; }
    RtlInitUnicodeString(&want, name);
    { PUCHAR p = (PUCHAR)buf;
      for (;;) { PSPI9 e = (PSPI9)p;
        if (e->ImageName.Buffer != NULL && e->ImageName.Length != 0) {
            UNICODE_STRING u = e->ImageName;
            if (RtlEqualUnicodeString(&u, &want, TRUE)) {
                result = (ULONG)(ULONG_PTR)e->PID; if (outCreate) *outCreate = e->Cr; break; } }
        if (e->Next == 0) break; p += e->Next; } }
    ExFreePoolWithTag(buf, 'pmiK');
    return result;
}

static ULONG64 FindModule(PCWSTR want)
{
    PPEB peb = (PPEB)PsGetProcessPeb(PsGetCurrentProcess());
    PVOID ldr; LIST_ENTRY* head; LIST_ENTRY* cur; UNICODE_STRING w;
    if (peb == NULL) return 0;
    ldr = *(PVOID*)((PUCHAR)peb + 0x18);
    if (ldr == NULL) return 0;
    head = (LIST_ENTRY*)((PUCHAR)ldr + 0x10);
    RtlInitUnicodeString(&w, want);
    for (cur = head->Flink; cur != head && cur != NULL; cur = cur->Flink) {
        PUCHAR e = (PUCHAR)cur; UNICODE_STRING bn;
        bn.Length = *(USHORT*)(e + 0x58); bn.MaximumLength = bn.Length; bn.Buffer = *(PWCH*)(e + 0x60);
        if (bn.Buffer == NULL || bn.Length == 0) continue;
        if (RtlEqualUnicodeString(&bn, &w, TRUE)) return *(ULONG64*)(e + 0x30);
    }
    return 0;
}

static VOID DoPatch(PEPROCESS proc)
{
    KAPC_STATE apc;
    ULONG64 ntBase = 0, k32Base = 0;
    ULONG i, ok = 0, skipped = 0, failed = 0;

    KeStackAttachProcess(proc, &apc);
    ntBase = FindModule(L"ntdll.dll");
    k32Base = FindModule(L"kernel32.dll");
    KLogF("[unhook3] ntdll=0x%llX k32=0x%llX\n", ntBase, k32Base);
    if (ntBase == 0) { KeUnstackDetachProcess(&apc); return; }

    for (i = 0; i < RTL_NUMBER_OF(g_patches); i++)
    {
        const PATCH* p = &g_patches[i];
        ULONG64 base, va;
        volatile ULONG64* pte;
        ULONG64 val;
        PUCHAR code;

        base = (wcscmp(p->Dll, L"ntdll.dll") == 0) ? ntBase : k32Base;
        if (base == 0) { failed++; continue; }
        va = base + p->Rva;

        pte = (volatile ULONG64*)(ULONG_PTR)(PTE_BASE + (((va >> 12) & 0xFFFFFFFFFULL) << 3));
        val = *pte;
        KLogF("[unhook3] %s pteVal=0x%llX\n", p->Api, val);

        if ((val & 1) == 0) { KLogF("[unhook3]   PTE 未present\n"); failed++; continue; }
        if ((val & 0x80) != 0) { KLogF("[unhook3]   大页，跳过\n"); failed++; continue; }

        *pte = val | 0x2;
        __invlpg((PVOID)(ULONG_PTR)va);

        code = (PUCHAR)(ULONG_PTR)va;
        if (code[0] != 0xE9) { KLogF("[unhook3]   未 hook (0x%02X)\n", code[0]); skipped++; }
        else {
            RtlCopyMemory(code, p->Orig, 8);
            if (code[0] == p->Orig[0] && code[1] == p->Orig[1]) { ok++; KLogF("[unhook3]   OK\n"); }
            else { failed++; KLogF("[unhook3]   校验失败\n"); }
        }

        *pte = val;
        __invlpg((PVOID)(ULONG_PTR)va);
    }

    KeUnstackDetachProcess(&apc);
    KLogF("[unhook3] result ok=%lu skip=%lu fail=%lu\n", ok, skipped, failed);
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl, ct, ct2;
    ULONG waited = 0, pid = 0, last = 0, stable = 0;
    PEPROCESS proc = NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(ctx);
    ct.QuadPart = 0;
    KLog("[unhook3] waiter alive\n");
    for (;;) {
        pid = FindPid(L"r5apex_dx12.exe", &ct2);
        if (pid != 0 && pid == last && ct2.QuadPart == ct.QuadPart) stable += 500;
        else { last = pid; ct = ct2; stable = 0; }
        if (pid != 0 && stable >= (ULONG)SETTLE_SEC * 1000) break;
        dl.QuadPart = -5000000LL; KeDelayExecutionThread(KernelMode, FALSE, &dl);
        waited += 500;
        if (waited > 1800000) { KLog("[unhook3] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); }
    }
    KLogF("[unhook3] game pid=%lu\n", pid);
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    if (!NT_SUCCESS(st)) { KLogF("[unhook3] lookup=0x%X\n", st); PsTerminateSystemThread(st); }
    DoPatch(proc);
    ObDereferenceObject(proc);
    KLog("[unhook3] done\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h = NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    KLog("\n[unhook3] === entry ===\n");
    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, Waiter, NULL);
    if (NT_SUCCESS(st) && h != NULL) ZwClose(h);
    KLogF("[unhook3] thread=0x%X\n", st);
    { LARGE_INTEGER d; d.QuadPart = -30000000LL; KeDelayExecutionThread(KernelMode, FALSE, &d); }
    return STATUS_SUCCESS;
}

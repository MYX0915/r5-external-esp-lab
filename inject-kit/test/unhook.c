// unhook.sys -- 还原游戏进程内 ntdll/kernel32 被 Javelin inline hook 的 API 序言
//   手法：attach 目标 → CR0.WP=0 → 直接写只读代码页 → 恢复 CR0
#include <ntifs.h>
#include <ntstrsafe.h>

#define LOG_FILE  L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define SETTLE_SEC 20

NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSYSAPI BOOLEAN NTAPI MmIsAddressValid(PVOID);
NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
#define MM_ALLOCATE_FULLY_REQUIRED 0x1

typedef struct _SPI7
{
    ULONG Next; ULONG Threads; LARGE_INTEGER W; ULONG HF; ULONG HW;
    ULONGLONG CT; LARGE_INTEGER Cr; LARGE_INTEGER U; LARGE_INTEGER K;
    UNICODE_STRING ImageName; LONG BP; HANDLE PID;
} SPI7, *PSPI7;

typedef struct _PATCH
{
    PCWSTR Dll;
    PCSTR  Api;
    ULONG  Rva;
    UCHAR  Orig[8];
} PATCH;

static const PATCH g_patches[] =
{
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
static VOID KLog(PCSTR t)
{ size_t n = 0; RtlStringCchLengthA(t, 2048, &n); WriteA(LOG_FILE, t, (ULONG)n); }
static VOID KLogF(PCSTR f, ...)
{ CHAR b[512]; va_list ap; va_start(ap, f); RtlStringCchVPrintfA(b, sizeof(b), f, ap); va_end(ap); KLog(b); }

static ULONG FindPid(PCWSTR name, LARGE_INTEGER* outCreate)
{
    ULONG size = 1 << 20, ret = 0, result = 0;
    PVOID buf; NTSTATUS st; UNICODE_STRING want;
    buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'pmiK');
    if (buf == NULL) return 0;
    st = ZwQuerySystemInformation(5, buf, size, &ret);
    if (st == STATUS_INFO_LENGTH_MISMATCH && ret > size) {
        ExFreePoolWithTag(buf, 'pmiK');
        size = ret + 0x1000;
        buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'pmiK');
        if (buf == NULL) return 0;
        st = ZwQuerySystemInformation(5, buf, size, &ret);
    }
    if (!NT_SUCCESS(st)) { ExFreePoolWithTag(buf, 'pmiK'); return 0; }
    RtlInitUnicodeString(&want, name);
    { PUCHAR p = (PUCHAR)buf;
      for (;;) {
          PSPI7 e = (PSPI7)p;
          if (e->ImageName.Buffer != NULL && e->ImageName.Length != 0) {
              UNICODE_STRING u = e->ImageName;
              if (RtlEqualUnicodeString(&u, &want, TRUE)) {
                  result = (ULONG)(ULONG_PTR)e->PID;
                  if (outCreate) *outCreate = e->Cr;
                  break;
              }
          }
          if (e->Next == 0) break;
          p += e->Next;
      } }
    ExFreePoolWithTag(buf, 'pmiK');
    return result;
}

static ULONG64 FindModule(PCWSTR want)
{
    PPEB peb = (PPEB)PsGetProcessPeb(PsGetCurrentProcess());
    PVOID ldr; LIST_ENTRY* head; LIST_ENTRY* cur;
    UNICODE_STRING w;

    if (peb == NULL) return 0;
    ldr = *(PVOID*)((PUCHAR)peb + 0x18);
    if (ldr == NULL) return 0;
    head = (LIST_ENTRY*)((PUCHAR)ldr + 0x10);
    RtlInitUnicodeString(&w, want);

    for (cur = head->Flink; cur != head && cur != NULL; cur = cur->Flink)
    {
        PUCHAR e = (PUCHAR)cur;
        UNICODE_STRING bn;
        bn.Length = *(USHORT*)(e + 0x58);
        bn.MaximumLength = bn.Length;
        bn.Buffer = *(PWCH*)(e + 0x60);
        if (bn.Buffer == NULL || bn.Length == 0) continue;
        if (RtlEqualUnicodeString(&bn, &w, TRUE)) return *(ULONG64*)(e + 0x30);
    }
    return 0;
}

static BOOLEAN WriteViaMdl(PVOID addr, const UCHAR* data, ULONG len)
{
    PMDL mdl;
    PVOID map;

    mdl = IoAllocateMdl(addr, len, FALSE, FALSE, NULL);
    if (mdl == NULL) return FALSE;

    MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
    map = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (map == NULL)
    {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return FALSE;
    }
    RtlCopyMemory(map, data, len);
    MmUnmapLockedPages(map, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return TRUE;
}

static VOID DoPatch(PEPROCESS proc)
{
    KAPC_STATE apc;
    ULONG64 ntBase = 0, k32Base = 0;
    ULONG i, ok = 0, skipped = 0, failed = 0;

    KeStackAttachProcess(proc, &apc);
    ntBase = FindModule(L"ntdll.dll");
    k32Base = FindModule(L"kernel32.dll");
    KLogF("[unhook] ntdll=0x%llX kernel32=0x%llX\n", ntBase, k32Base);
    if (ntBase == 0) { KeUnstackDetachProcess(&apc); return; }

    for (i = 0; i < RTL_NUMBER_OF(g_patches); i++)
    {
        const PATCH* p = &g_patches[i];
        ULONG64 base;
        PUCHAR addr;

        base = (wcscmp(p->Dll, L"ntdll.dll") == 0) ? ntBase : k32Base;
        if (base == 0) { failed++; continue; }
        addr = (PUCHAR)(ULONG_PTR)(base + p->Rva);

        if (!WriteViaMdl(addr, p->Orig, 8))
        {
            KLogF("[unhook] %-24s MDL 写入失败\n", p->Api);
            failed++;
            continue;
        }
        if (addr[0] == p->Orig[0] && addr[1] == p->Orig[1])
        {
            ok++;
            KLogF("[unhook] %-24s OK\n", p->Api);
        }
        else
        {
            failed++;
            KLogF("[unhook] %-24s 校验失败 (0x%02X)\n", p->Api, addr[0]);
        }
    }

    KeUnstackDetachProcess(&apc);
    KLogF("[unhook] result ok=%lu skip=%lu fail=%lu\n", ok, skipped, failed);
}
static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl, ct, ct2;
    ULONG waited = 0, pid = 0, last = 0, stable = 0;
    PEPROCESS proc = NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(ctx);
    ct.QuadPart = 0;
    KLog("[unhook] waiter alive\n");
    for (;;)
    {
        pid = FindPid(L"r5apex_dx12.exe", &ct2);
        if (pid != 0 && pid == last && ct2.QuadPart == ct.QuadPart) stable += 500;
        else { last = pid; ct = ct2; stable = 0; }
        if (pid != 0 && stable >= (ULONG)SETTLE_SEC * 1000) break;
        dl.QuadPart = -5000000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &dl);
        waited += 500;
        if (waited > 1800000) { KLog("[unhook] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); }
    }
    KLogF("[unhook] game pid=%lu\n", pid);
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    if (!NT_SUCCESS(st)) { KLogF("[unhook] lookup=0x%X\n", st); PsTerminateSystemThread(st); }
    DoPatch(proc);
    ObDereferenceObject(proc);
    KLog("[unhook] done\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h = NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    KLog("\n[unhook] === entry ===\n");
    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, Waiter, NULL);
    if (NT_SUCCESS(st) && h != NULL) ZwClose(h);
    KLogF("[unhook] thread=0x%X\n", st);
    { LARGE_INTEGER d; d.QuadPart = -30000000LL; KeDelayExecutionThread(KernelMode, FALSE, &d); }
    return STATUS_SUCCESS;
}

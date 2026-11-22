// unhook2.sys -- 用 PTE 直接改页属性来还原 inline hook
//   1) 先 ZwReadVirtualMemory 把目标页"拉进内存"（避免访问未驻留页崩溃）
//   2) __readcr3 走 4 级页表，用 MmMapIoSpaceEx 映射页表页，修改 PTE/大页 PDE 的 RW 位
//   3) __invlpg 刷 TLB → 写 8 字节原序言 → 恢复 RW 位 → 再刷 TLB
//   全程不调用会抛异常的 API（不用 MmProbeAndLockPages / 不改保护）
#include <ntifs.h>
#include <ntstrsafe.h>

#define LOG_FILE   L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define SETTLE_SEC 20

NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);


typedef struct _SPI8
{
    ULONG Next; ULONG Threads; LARGE_INTEGER W; ULONG HF; ULONG HW;
    ULONGLONG CT; LARGE_INTEGER Cr; LARGE_INTEGER U; LARGE_INTEGER K;
    UNICODE_STRING ImageName; LONG BP; HANDLE PID;
} SPI8, *PSPI8;

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
{ CHAR b[400]; va_list ap; va_start(ap, f); RtlStringCchVPrintfA(b, sizeof(b), f, ap); va_end(ap); KLog(b); }

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
          PSPI8 e = (PSPI8)p;
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

/* 找到 VA 对应的"最终"页表项（PTE 或 2MB 大页 PDE）的物理地址及其值 */
static ULONG64 g_DirBase = 0;
static BOOLEAN WalkToPte(ULONG64 va, ULONG64* ptePhys, ULONG64* pteVal, BOOLEAN* isLarge)
{
    ULONG64 cr3 = (g_DirBase != 0 ? g_DirBase : __readcr3()) & ~0xFFFULL;
    ULONG64 table = cr3;
    int level;
    ULONG idx;

    *isLarge = FALSE;
    for (level = 0; level < 4; level++)
    {
        PHYSICAL_ADDRESS pa; PVOID map; ULONG64 entry;

        pa.QuadPart = (LONGLONG)table;
        map = MmMapIoSpaceEx(pa, 0x1000, PAGE_READWRITE);
        if (map == NULL) return FALSE;

        switch (level)
        {
            case 0: idx = (ULONG)((va >> 39) & 0x1FF); break;
            case 1: idx = (ULONG)((va >> 30) & 0x1FF); break;
            case 2: idx = (ULONG)((va >> 21) & 0x1FF); break;
            default: idx = (ULONG)((va >> 12) & 0x1FF); break;
        }
        entry = ((volatile ULONG64*)map)[idx];
        MmUnmapIoSpace(map, 0x1000);

        if ((entry & 1) == 0) return FALSE;              /* not present */

        if (level == 2 && (entry & 0x80))                /* 2MB large page */
        {
            *ptePhys = table + (ULONG64)idx * 8;
            *pteVal = entry;
            *isLarge = TRUE;
            return TRUE;
        }
        if (level == 3)
        {
            *ptePhys = table + (ULONG64)idx * 8;
            *pteVal = entry;
            return TRUE;
        }
        table = entry & 0x000FFFFFFFFFF000ULL;
    }
    return FALSE;
}

static BOOLEAN SetPteRw(ULONG64 ptePhys, ULONG64 value, BOOLEAN rw)
{
    PHYSICAL_ADDRESS pa; PVOID map; volatile ULONG64* p;
    ULONG64 newv = value;

    if (rw) newv |= 0x2;
    else    newv &= ~0x2ULL;

    pa.QuadPart = (LONGLONG)ptePhys;
    map = MmMapIoSpaceEx(pa, 0x1000, PAGE_READWRITE);
    if (map == NULL) return FALSE;
    p = (volatile ULONG64*)((PUCHAR)map + (ptePhys & 0xFFF));
    *p = newv;
    MmUnmapIoSpace(map, 0x1000);
    return TRUE;
}

static VOID DoPatch(PEPROCESS proc)
{
    KAPC_STATE apc;
    ULONG64 ntBase = 0, k32Base = 0;
    ULONG i, ok = 0, failed = 0, skipped = 0;

    g_DirBase = *(ULONG64*)((PUCHAR)proc + 0x28);
    KLogF("[unhook2] DirBase=0x%llX\n", g_DirBase);
    KeStackAttachProcess(proc, &apc);
    ntBase = FindModule(L"ntdll.dll");
    k32Base = FindModule(L"kernel32.dll");
    KLogF("[unhook2] ntdll=0x%llX k32=0x%llX\n", ntBase, k32Base);
    if (ntBase == 0) { KeUnstackDetachProcess(&apc); return; }

    for (i = 0; i < RTL_NUMBER_OF(g_patches); i++)
    {
        const PATCH* p = &g_patches[i];
        ULONG64 base, va, ptePhys = 0, pteVal = 0;
        BOOLEAN isLarge = FALSE;
        CHAR tmp[8];
        SIZE_T got = 0;
        PUCHAR code;

        base = (wcscmp(p->Dll, L"ntdll.dll") == 0) ? ntBase : k32Base;
        if (base == 0) { failed++; continue; }
        va = base + p->Rva;

        KLogF("[unhook2] %s @ 0x%llX\n", p->Api, va);

        /* 1) 页表遍历会告诉我们页是否存在；不存在就跳过，绝不直接解引用 */
        UNREFERENCED_PARAMETER(tmp);
        UNREFERENCED_PARAMETER(got);

        /* 2) 走页表 */
        if (!WalkToPte(va, &ptePhys, &pteVal, &isLarge))
        {
            KLogF("[unhook2]   页表遍历失败\n");
            failed++;
            continue;
        }
        KLogF("[unhook2]   pte=0x%llX val=0x%llX large=%d\n", ptePhys, pteVal, isLarge);

        /* 3) 置 RW */
        if (!SetPteRw(ptePhys, pteVal, TRUE)) { KLogF("[unhook2]   PTE 置RW失败\n"); failed++; continue; }
        __invlpg((PVOID)(ULONG_PTR)va);

        /* 4) 写原序言 */
        code = (PUCHAR)(ULONG_PTR)va;
        if (code[0] != 0xE9)
        {
            KLogF("[unhook2]   未 hook (0x%02X)\n", code[0]);
            skipped++;
        }
        else
        {
            RtlCopyMemory(code, p->Orig, 8);
            if (code[0] == p->Orig[0] && code[1] == p->Orig[1]) { ok++; KLogF("[unhook2]   OK\n"); }
            else { failed++; KLogF("[unhook2]   校验失败\n"); }
        }

        /* 5) 恢复 RW 位 */
        SetPteRw(ptePhys, pteVal, FALSE);
        __invlpg((PVOID)(ULONG_PTR)va);
    }

    KeUnstackDetachProcess(&apc);
    KLogF("[unhook2] result ok=%lu skip=%lu fail=%lu\n", ok, skipped, failed);
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl, ct, ct2;
    ULONG waited = 0, pid = 0, last = 0, stable = 0;
    PEPROCESS proc = NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(ctx);
    ct.QuadPart = 0;
    KLog("[unhook2] waiter alive\n");
    for (;;)
    {
        pid = FindPid(L"r5apex_dx12.exe", &ct2);
        if (pid != 0 && pid == last && ct2.QuadPart == ct.QuadPart) stable += 500;
        else { last = pid; ct = ct2; stable = 0; }
        if (pid != 0 && stable >= (ULONG)SETTLE_SEC * 1000) break;
        dl.QuadPart = -5000000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &dl);
        waited += 500;
        if (waited > 1800000) { KLog("[unhook2] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); }
    }
    KLogF("[unhook2] game pid=%lu\n", pid);
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    if (!NT_SUCCESS(st)) { KLogF("[unhook2] lookup=0x%X\n", st); PsTerminateSystemThread(st); }
    DoPatch(proc);
    ObDereferenceObject(proc);
    KLog("[unhook2] done\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h = NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    KLog("\n[unhook2] === entry ===\n");
    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, Waiter, NULL);
    if (NT_SUCCESS(st) && h != NULL) ZwClose(h);
    KLogF("[unhook2] thread=0x%X\n", st);
    { LARGE_INTEGER d; d.QuadPart = -30000000LL; KeDelayExecutionThread(KernelMode, FALSE, &d); }
    return STATUS_SUCCESS;
}

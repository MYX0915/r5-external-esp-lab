// upe.sys -- 扫描游戏进程地址空间，找出"不在 PEB->Ldr 里"的 PE 镜像并 dump
//   流程：等游戏 → attach → ZwQueryVirtualMemory 遍历 → 校验 MZ/PE → 与 Ldr 模块表比对 → dump
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntimage.h>

#define LOG_FILE   L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define OUT_DIR    L"\\??\\C:\\ProgramData\\"
#define SETTLE_SEC 20

NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
NTSYSAPI BOOLEAN NTAPI MmIsAddressValid(PVOID);

typedef struct _SPI5
{
    ULONG Next; ULONG Threads; LARGE_INTEGER W; ULONG HF; ULONG HW;
    ULONGLONG CT; LARGE_INTEGER Cr; LARGE_INTEGER U; LARGE_INTEGER K;
    UNICODE_STRING ImageName; LONG BP; HANDLE PID;
} SPI5, *PSPI5;

typedef struct _MBI
{
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    ULONG Part1;
    SIZE_T RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
    ULONG Part2;
} MBI, *PMBI;

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
          PSPI5 e = (PSPI5)p;
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

/* 收集 PEB->Ldr 里所有模块基址 */
static ULONG CollectBases(ULONG64* arr, ULONG max)
{
    PPEB peb = (PPEB)PsGetProcessPeb(PsGetCurrentProcess());
    PVOID ldr; LIST_ENTRY* head; LIST_ENTRY* cur; ULONG n = 0;

    if (peb == NULL) return 0;
    ldr = *(PVOID*)((PUCHAR)peb + 0x18);
    if (ldr == NULL) return 0;
    head = (LIST_ENTRY*)((PUCHAR)ldr + 0x10);
    for (cur = head->Flink; cur != head && cur != NULL && n < max; cur = cur->Flink)
    {
        PUCHAR e = (PUCHAR)cur;
        arr[n++] = *(ULONG64*)(e + 0x30);
    }
    return n;
}

static BOOLEAN IsKnown(ULONG64* arr, ULONG n, ULONG64 base)
{
    ULONG i;
    for (i = 0; i < n; i++) if (arr[i] == base) return TRUE;
    return FALSE;
}

static VOID DumpImage(ULONG64 base, ULONG size, ULONG idx)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    WCHAR path[160]; PCHAR buf; ULONG off = 0;

    RtlStringCchPrintfW(path, RTL_NUMBER_OF(path), L"\\??\\C:\\ProgramData\\upe_%llX.bin", base);
    RtlInitUnicodeString(&p, path);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, GENERIC_WRITE | SYNCHRONIZE, &oa, &io, NULL,
                                 FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0))) return;

    buf = (PCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, 'pmiK');
    if (buf == NULL) { ZwClose(h); return; }
    while (off < size)
    {
        ULONG nn = min(size - off, 0x10000);
        PUCHAR src = (PUCHAR)(ULONG_PTR)(base + off);
        if (MmIsAddressValid(src)) RtlCopyMemory(buf, src, nn);
        else RtlZeroMemory(buf, nn);
        ZwWriteFile(h, NULL, NULL, NULL, &io, buf, nn, NULL, NULL);
        off += nn;
    }
    ExFreePoolWithTag(buf, 'pmiK');
    ZwClose(h);
    KLogF("[upe] dumped 0x%llX size=0x%X (idx %lu)\n", base, size, idx);
}

static VOID Scan(PEPROCESS proc)
{
    KAPC_STATE apc;
    ULONG64* bases;
    ULONG nbases = 0, found = 0;
    ULONG64 addr = 0;
    MBI mbi;
    SIZE_T ret = 0;
    NTSTATUS st;

    bases = (ULONG64*)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * 8, 'pmiK');
    if (bases == NULL) { KLog("[upe] pool fail\n"); return; }

    KeStackAttachProcess(proc, &apc);
    nbases = CollectBases(bases, 4096);
    KLogF("[upe] ldr modules=%lu\n", nbases);

    /* 扫描用户态地址范围 */
    for (addr = 0x10000; addr < 0x00007FFFFFFF0000ULL; )
    {
        MBI m;
        RtlZeroMemory(&m, sizeof(m));
        ret = 0;
        st = ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)(ULONG_PTR)addr, 0,
                                  &m, sizeof(m), &ret);
        if (!NT_SUCCESS(st) || m.RegionSize == 0)
        {
            addr += 0x10000;
            continue;
        }
        {
            ULONG64 next = (ULONG64)m.BaseAddress + m.RegionSize;
            /* 只看已提交、可读的区域 */
            if (m.State == 0x1000 /* MEM_COMMIT */ && (m.Protect & 0xFF) != 0x01 /* NOACCESS */)
            {
                PUCHAR p = (PUCHAR)m.BaseAddress;
                if (MmIsAddressValid(p) && p[0] == 'M' && p[1] == 'Z')
                {
                    ULONG64 base = (ULONG64)m.BaseAddress;
                    if (!IsKnown(bases, nbases, base))
                    {
                        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)p;
                        if (dos->e_lfanew > 0 && dos->e_lfanew < 0x1000 &&
                            MmIsAddressValid(p + dos->e_lfanew))
                        {
                            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(p + dos->e_lfanew);
                            if (nt->Signature == IMAGE_NT_SIGNATURE &&
                                nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                            {
                                ULONG sizeImg = nt->OptionalHeader.SizeOfImage;
                                found++;
                                KLogF("[upe] UNLISTED 0x%llX size=0x%X ts=0x%X prot=0x%X\n",
                                      base, sizeImg, nt->FileHeader.TimeDateStamp, m.Protect);
                                if (sizeImg > 0x1000 && sizeImg <= 0x2000000)
                                    DumpImage(base, sizeImg, found);
                            }
                        }
                    }
                }
            }
            addr = next;
        }
        if (found > 60) break;
    }
    KeUnstackDetachProcess(&apc);
    ExFreePoolWithTag(bases, 'pmiK');
    KLogF("[upe] unlisted=%lu\n", found);
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl, ct, ct2;
    ULONG waited = 0, pid = 0, last = 0, stable = 0;
    PEPROCESS proc = NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(ctx);
    ct.QuadPart = 0;
    KLog("[upe] waiter alive\n");
    for (;;)
    {
        pid = FindPid(L"r5apex_dx12.exe", &ct2);
        if (pid != 0 && pid == last && ct2.QuadPart == ct.QuadPart) stable += 500;
        else { last = pid; ct = ct2; stable = 0; }
        if (pid != 0 && stable >= (ULONG)SETTLE_SEC * 1000) break;
        dl.QuadPart = -5000000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &dl);
        waited += 500;
        if (waited > 1800000) { KLog("[upe] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); }
    }
    KLogF("[upe] game pid=%lu\n", pid);
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    if (!NT_SUCCESS(st)) { KLogF("[upe] lookup=0x%X\n", st); PsTerminateSystemThread(st); }
    Scan(proc);
    ObDereferenceObject(proc);
    KLog("[upe] done\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h = NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    KLog("\n[upe] === entry ===\n");
    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, Waiter, NULL);
    if (NT_SUCCESS(st) && h != NULL) ZwClose(h);
    KLogF("[upe] thread=0x%X\n", st);
    { LARGE_INTEGER d; d.QuadPart = -30000000LL; KeDelayExecutionThread(KernelMode, FALSE, &d); }
    return STATUS_SUCCESS;
}

// dumper.sys -- 扫描内核地址空间里的 PE 镜像，把可疑的（不在模块列表里的）驱动 dump 出来
//   - 用 MmIsAddressValid 逐页校验，避免访问未映射内存触发蓝屏（映射驱动无 SEH）
//   - 输出：C:\ProgramData\kmods.txt（清单） + C:\ProgramData\kmod_<base>.bin（镜像）
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntimage.h>

#define LOG_FILE  L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define IDX_FILE  L"\\??\\C:\\ProgramData\\kmods.txt"
#define SETTLE_SEC 20

NTSYSAPI BOOLEAN NTAPI MmIsAddressValid(PVOID VirtualAddress);
NTSYSAPI PVOID NTAPI MmGetSystemRoutineAddress(PUNICODE_STRING);

static ULONG64 g_modBase[512];
static ULONG   g_modCount = 0;

static VOID CollectModules(VOID)
{
    UNICODE_STRING nm; LIST_ENTRY* head; LIST_ENTRY* cur;
    RtlInitUnicodeString(&nm, L"PsLoadedModuleList");
    head = (LIST_ENTRY*)MmGetSystemRoutineAddress(&nm);
    if (!head) return;
    for (cur = head->Flink; cur != head && cur; cur = cur->Flink)
    {
        PUCHAR e = (PUCHAR)cur;
        if (g_modCount < 512) g_modBase[g_modCount++] = *(ULONG64*)(e + 0x30);
    }
}

static BOOLEAN IsListed(ULONG64 base)
{
    ULONG i;
    for (i = 0; i < g_modCount; i++) if (g_modBase[i] == base) return TRUE;
    return FALSE;
}
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

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
{ CHAR b[512]; va_list ap; va_start(ap, f); RtlStringCchVPrintfA(b, sizeof(b), f, ap); va_end(ap); KLog(b); }

static VOID AppendIdx(PCSTR s)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h; size_t n = 0;
    RtlInitUnicodeString(&p, IDX_FILE);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &io, NULL,
                                 FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0))) return;
    RtlStringCchLengthA(s, 1024, &n);
    ZwWriteFile(h, NULL, NULL, NULL, &io, (PVOID)s, (ULONG)n, NULL, NULL);
    ZwFlushBuffersFile(h, &io); ZwClose(h);
}

/* 逐页安全读取：任何一页 invalid 就放弃 */
static BOOLEAN SafeRead(PVOID va, PVOID buf, ULONG len)
{
    PUCHAR s = (PUCHAR)va, d = (PUCHAR)buf;
    while (len)
    {
        ULONG chunk = min(len, 0x1000 - ((ULONG_PTR)s & 0xFFF));
        if (!MmIsAddressValid(s)) return FALSE;
        RtlCopyMemory(d, s, chunk);
        s += chunk; d += chunk; len -= chunk;
    }
    return TRUE;
}

/* 把镜像写到文件 */
static BOOLEAN DumpImage(ULONG64 base, ULONG size, PCSTR name)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    WCHAR path[128]; PCHAR buf;
    ULONG off = 0;

    buf = (PCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x1000, 'pmiK');
    if (buf == NULL) return FALSE;

    RtlStringCchPrintfW(path, RTL_NUMBER_OF(path), L"\\??\\C:\\ProgramData\\%S", name);
    RtlInitUnicodeString(&p, path);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, GENERIC_WRITE | SYNCHRONIZE, &oa, &io, NULL,
                                 FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0))) return FALSE;

    while (off < size)
    {
        ULONG chunk = min(size - off, 0x1000);
        if (!SafeRead((PVOID)(ULONG_PTR)(base + off), buf, chunk))
            RtlZeroMemory(buf, chunk);
        ZwWriteFile(h, NULL, NULL, NULL, &io, buf, chunk, NULL, NULL);
        off += chunk;
    }
    ExFreePoolWithTag(buf, 'pmiK');
    ZwClose(h);
    return off == size;
}

typedef struct _SPI_HEAD
{
    ULONG NextEntryOffset; ULONG NumberOfThreads; LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount; ULONG NumberOfThreadsHighWatermark; ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime, UserTime, KernelTime; UNICODE_STRING ImageName;
    LONG BasePriority; HANDLE UniqueProcessId;
} SPI_HEAD, *PSPI_HEAD;

static ULONG FindPid(PCWSTR name, LARGE_INTEGER* outCreate)
{
    ULONG size = 1 << 20, ret = 0; PVOID buf; NTSTATUS st; UNICODE_STRING want;
    buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'pmiK'); if (!buf) return 0;
    st = ZwQuerySystemInformation(5, buf, size, &ret);
    if (st == STATUS_INFO_LENGTH_MISMATCH && ret > size) {
        ExFreePoolWithTag(buf, 'pmiK'); size = ret + 0x1000;
        buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'pmiK'); if (!buf) return 0;
        st = ZwQuerySystemInformation(5, buf, size, &ret);
    }
    if (!NT_SUCCESS(st)) { ExFreePoolWithTag(buf, 'pmiK'); return 0; }
    RtlInitUnicodeString(&want, name);
    { PUCHAR p = (PUCHAR)buf;
      for (;;) { PSPI_HEAD e = (PSPI_HEAD)p;
        if (e->ImageName.Buffer && e->ImageName.Length) {
            UNICODE_STRING u; u.Buffer = e->ImageName.Buffer; u.Length = e->ImageName.Length; u.MaximumLength = e->ImageName.Length;
            if (RtlEqualUnicodeString(&u, &want, TRUE)) { if (outCreate) *outCreate = e->CreateTime;
                ExFreePoolWithTag(buf, 'pmiK'); return (ULONG)(ULONG_PTR)e->UniqueProcessId; } }
        if (!e->NextEntryOffset) break; p += e->NextEntryOffset; } }
    ExFreePoolWithTag(buf, 'pmiK'); return 0;
}

/* 在某段内存里找 ASCII 关键字（不区分大小写，仅 ASCII） */
static BOOLEAN ContainsAscii(PUCHAR buf, ULONG len, PCSTR needle)
{
    ULONG nl = (ULONG)strlen(needle), i;
    if (!nl || len < nl) return FALSE;
    for (i = 0; i + nl <= len; i++) {
        ULONG k = 0;
        while (k < nl) {
            CHAR a = (CHAR)buf[i + k], b = needle[k];
            if (a >= 'A' && a <= 'Z') a = (CHAR)(a + 32);
            if (b >= 'A' && b <= 'Z') b = (CHAR)(b + 32);
            if (a != b) break;
            k++;
        }
        if (k == nl) return TRUE;
    }
    return FALSE;
}

static VOID ScanKernelSpace(VOID)
{
    ULONG64 start = 0xFFFFF80000000000ULL, end = 0xFFFFF88000000000ULL;
    ULONG64 va;
    ULONG found = 0, dumped = 0;

    CollectModules();
    KLogF("[dumper3] listed modules=%lu\n", g_modCount);
    KLog("[dumper3] scan start\n");
    for (va = start; va < end; va += 0x1000)
    {
        PUCHAR p = (PUCHAR)(ULONG_PTR)va;
        PIMAGE_DOS_HEADER dos;
        PIMAGE_NT_HEADERS nt;

        if (!MmIsAddressValid(p)) continue;
        if (p[0] != 'M' || p[1] != 'Z') continue;

        dos = (PIMAGE_DOS_HEADER)p;
        if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000) continue;
        if (!MmIsAddressValid(p + dos->e_lfanew)) continue;
        nt = (PIMAGE_NT_HEADERS)(p + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) continue;

        {
            ULONG size = nt->OptionalHeader.SizeOfImage;
            ULONG ts = nt->FileHeader.TimeDateStamp;
            BOOLEAN suspicious = FALSE;
            static CHAR head[0x2000];   /* 静态：避免栈溢出 */

            if (size == 0 || size > 0x4000000) continue;
            found++;

            /* 看头部有没有 EA/Javelin 特征 */
            if (SafeRead(p, head, 0x2000)) {
                if (ContainsAscii((PUCHAR)head, 0x2000, "eaac") ||
                    ContainsAscii((PUCHAR)head, 0x2000, "javelin") ||
                    ContainsAscii((PUCHAR)head, 0x2000, "Electronic Arts") ||
                    ContainsAscii((PUCHAR)head, 0x2000, "eaanticheat"))
                    suspicious = TRUE;
            }

            KLogF("[dumper3] PE base=0x%llX size=0x%X ts=0x%X%s\n",
                  va, size, ts, suspicious ? "  <== SUSPICIOUS" : "");

            if (!IsListed(va)) suspicious = TRUE;   /* 隐藏镜像一律 dump */
            if (suspicious) {
                CHAR fname[64];
                RtlStringCchPrintfA(fname, RTL_NUMBER_OF(fname), "kmod_%llX.bin", va);
                if (DumpImage(va, size, fname)) {
                    dumped++;
                    KLogF("[dumper3] dumped -> %s\n", fname);
                    AppendIdx(fname);
                } else KLogF("[dumper3] dump failed for 0x%llX\n", va);
            }
        }
    }
    KLogF("[dumper3] scan done: PE=%lu dumped=%lu\n", found, dumped);
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl, ct, ct2; ULONG waited = 0, pid = 0, last = 0, stable = 0;
    UNREFERENCED_PARAMETER(ctx);

    KLog("[dumper3] waiter alive\n");
    for (;;) {
        pid = FindPid(L"r5apex_dx12.exe", &ct2);
        if (pid && pid == last && ct2.QuadPart == ct.QuadPart) stable += 500;
        else { last = pid; ct = ct2; stable = 0; }
        if (pid && stable >= (ULONG)SETTLE_SEC * 1000) break;
        dl.QuadPart = -5000000LL; KeDelayExecutionThread(KernelMode, FALSE, &dl);
        waited += 500;
        if (waited > 1800000) { KLog("[dumper3] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); }
    }
    KLogF("[dumper3] game up pid=%lu, scanning kernel space...\n", pid);
    ScanKernelSpace();
    KLog("[dumper3] done\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h = NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    KLog("\n[dumper3] === entry ===\n");
    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, Waiter, NULL);
    if (NT_SUCCESS(st) && h) ZwClose(h);
    KLogF("[dumper3] thread=0x%X\n", st);
    { LARGE_INTEGER d; d.QuadPart = -30000000LL; KeDelayExecutionThread(KernelMode, FALSE, &d); }
    return STATUS_SUCCESS;
}

// udll.sys -- 从游戏进程 dump 指定模块的完整镜像（用于和磁盘文件比对，找用户态 hook）
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntimage.h>

#define LOG_FILE  L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define SETTLE_SEC 20

NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSYSAPI BOOLEAN NTAPI MmIsAddressValid(PVOID);

typedef struct _SPI6
{
    ULONG Next; ULONG Threads; LARGE_INTEGER W; ULONG HF; ULONG HW;
    ULONGLONG CT; LARGE_INTEGER Cr; LARGE_INTEGER U; LARGE_INTEGER K;
    UNICODE_STRING ImageName; LONG BP; HANDLE PID;
} SPI6, *PSPI6;

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
          PSPI6 e = (PSPI6)p;
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

static VOID DumpMod(ULONG64 base, ULONG size, PCWSTR wname)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    WCHAR path[180]; PCHAR buf; ULONG off = 0;

    RtlStringCchPrintfW(path, RTL_NUMBER_OF(path), L"\\??\\C:\\ProgramData\\udll_%ws.bin", wname);
    RtlInitUnicodeString(&p, path);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, GENERIC_WRITE | SYNCHRONIZE, &oa, &io, NULL,
                                 FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0))) { KLog("[udll] create failed\n"); return; }

    buf = (PCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, 'pmiK');
    if (buf == NULL) { ZwClose(h); return; }
    while (off < size)
    {
        ULONG n = min(size - off, 0x10000);
        PUCHAR src = (PUCHAR)(ULONG_PTR)(base + off);
        if (MmIsAddressValid(src)) RtlCopyMemory(buf, src, n);
        else RtlZeroMemory(buf, n);
        ZwWriteFile(h, NULL, NULL, NULL, &io, buf, n, NULL, NULL);
        off += n;
    }
    ExFreePoolWithTag(buf, 'pmiK');
    ZwClose(h);
    KLogF("[udll] dumped base=0x%llX size=0x%X\n", base, size);
}

static VOID EnumAndDump(PEPROCESS proc)
{
    KAPC_STATE apc;
    PPEB peb; PVOID ldr; LIST_ENTRY* head; LIST_ENTRY* cur;
    ULONG nmod = 0, ndump = 0;

    KeStackAttachProcess(proc, &apc);
    peb = (PPEB)PsGetProcessPeb(PsGetCurrentProcess());
    if (peb == NULL) { KeUnstackDetachProcess(&apc); KLog("[udll] no peb\n"); return; }
    ldr = *(PVOID*)((PUCHAR)peb + 0x18);
    if (ldr == NULL) { KeUnstackDetachProcess(&apc); KLog("[udll] no ldr\n"); return; }
    head = (LIST_ENTRY*)((PUCHAR)ldr + 0x10);

    for (cur = head->Flink; cur != head && cur != NULL; cur = cur->Flink)
    {
        PUCHAR e = (PUCHAR)cur;
        ULONG64 dllBase = *(ULONG64*)(e + 0x30);
        ULONG   sizeImg = *(ULONG*)(e + 0x40);
        UNICODE_STRING bn;
        bn.Length = *(USHORT*)(e + 0x58);
        bn.MaximumLength = bn.Length;
        bn.Buffer = *(PWCH*)(e + 0x60);
        if (bn.Buffer == NULL || bn.Length == 0) continue;
        nmod++;

        /* 名字转换后判断 */
        {
            WCHAR nm[128];
            ULONG i;
            for (i = 0; i < bn.Length / 2 && i < 127; i++)
            {
                WCHAR c = bn.Buffer[i];
                if (c >= L'A' && c <= L'Z') c = (WCHAR)(c + 32);
                nm[i] = c;
            }
            nm[i] = 0;

            if ((wcsstr(nm, L"ntdll") || wcsstr(nm, L"kernel32") || wcsstr(nm, L"kernelbase") ||
                 wcsstr(nm, L"win32u") || wcsstr(nm, L"gdi32full")) &&
                dllBase != 0 && sizeImg > 0x1000 && sizeImg < 0x8000000)
            {
                KLogF("[udll] dumping %S base=0x%llX size=0x%X\n", nm, dllBase, sizeImg);
                DumpMod(dllBase, sizeImg, nm);
                ndump++;
            }
        }
    }
    KeUnstackDetachProcess(&apc);
    KLogF("[udll] modules=%lu dumped=%lu\n", nmod, ndump);
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl, ct, ct2;
    ULONG waited = 0, pid = 0, last = 0, stable = 0;
    PEPROCESS proc = NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(ctx);
    ct.QuadPart = 0;
    KLog("[udll] waiter alive\n");
    for (;;)
    {
        pid = FindPid(L"r5apex_dx12.exe", &ct2);
        if (pid != 0 && pid == last && ct2.QuadPart == ct.QuadPart) stable += 500;
        else { last = pid; ct = ct2; stable = 0; }
        if (pid != 0 && stable >= (ULONG)SETTLE_SEC * 1000) break;
        dl.QuadPart = -5000000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &dl);
        waited += 500;
        if (waited > 1800000) { KLog("[udll] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); }
    }
    KLogF("[udll] game pid=%lu\n", pid);
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    if (!NT_SUCCESS(st)) { KLogF("[udll] lookup=0x%X\n", st); PsTerminateSystemThread(st); }
    EnumAndDump(proc);
    ObDereferenceObject(proc);
    KLog("[udll] done\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h = NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    KLog("\n[udll] === entry ===\n");
    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, Waiter, NULL);
    if (NT_SUCCESS(st) && h != NULL) ZwClose(h);
    KLogF("[udll] thread=0x%X\n", st);
    { LARGE_INTEGER d; d.QuadPart = -30000000LL; KeDelayExecutionThread(KernelMode, FALSE, &d); }
    return STATUS_SUCCESS;
}

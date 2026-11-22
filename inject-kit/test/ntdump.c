// ntdump.sys -- 等游戏起来后，把 ntoskrnl 的镜像整段写到磁盘，供离线比对（找中段 hook）
//   纯读取 + 文件写入，不调用对象管理器、不建线程之外的东西
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntimage.h>

#define LOG_FILE  L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define OUT_FILE  L"\\??\\C:\\ProgramData\\ntoskrnl_mem.bin"
#define SETTLE_SEC 20

NTSYSAPI PVOID NTAPI MmGetSystemRoutineAddress(PUNICODE_STRING);
NTSYSAPI BOOLEAN NTAPI MmIsAddressValid(PVOID);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

typedef struct _SPI3
{
    ULONG Next; ULONG Threads; LARGE_INTEGER W; ULONG HF; ULONG HW;
    ULONGLONG CT; LARGE_INTEGER Cr; LARGE_INTEGER U; LARGE_INTEGER K;
    UNICODE_STRING ImageName; LONG BP; HANDLE PID;
} SPI3, *PSPI3;

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

static ULONG FindPid(PCWSTR name, LARGE_INTEGER* outCreate)
{
    ULONG size = 1 << 20, ret = 0, result = 0;
    PVOID buf; NTSTATUS st; UNICODE_STRING want;

    buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'pmiK');
    if (buf == NULL) return 0;
    st = ZwQuerySystemInformation(5, buf, size, &ret);
    if (st == STATUS_INFO_LENGTH_MISMATCH && ret > size)
    {
        ExFreePoolWithTag(buf, 'pmiK');
        size = ret + 0x1000;
        buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'pmiK');
        if (buf == NULL) return 0;
        st = ZwQuerySystemInformation(5, buf, size, &ret);
    }
    if (!NT_SUCCESS(st)) { ExFreePoolWithTag(buf, 'pmiK'); return 0; }

    RtlInitUnicodeString(&want, name);
    { PUCHAR p = (PUCHAR)buf;
      for (;;)
      {
          PSPI3 e = (PSPI3)p;
          if (e->ImageName.Buffer != NULL && e->ImageName.Length != 0)
          {
              UNICODE_STRING u;
              u.Buffer = e->ImageName.Buffer;
              u.Length = e->ImageName.Length;
              u.MaximumLength = e->ImageName.MaximumLength;
              if (RtlEqualUnicodeString(&u, &want, TRUE))
              {
                  result = (ULONG)(ULONG_PTR)e->PID;
                  if (outCreate) *outCreate = e->Cr;
                  break;
              }
          }
          if (e->Next == 0) break;
          p += e->Next;
      }
    }
    ExFreePoolWithTag(buf, 'pmiK');
    return result;
}

static VOID DumpNt(VOID)
{
    UNICODE_STRING nm;
    LIST_ENTRY* head;
    LIST_ENTRY* cur;
    ULONG64 base = 0;
    ULONG size = 0;
    UNICODE_STRING want;

    RtlInitUnicodeString(&nm, L"PsLoadedModuleList");
    head = (LIST_ENTRY*)MmGetSystemRoutineAddress(&nm);
    if (head == NULL) { KLog("[ntdump] no module list\n"); return; }

    RtlInitUnicodeString(&want, L"ntoskrnl.exe");
    for (cur = head->Flink; cur != head && cur != NULL; cur = cur->Flink)
    {
        PUCHAR e = (PUCHAR)cur;
        USHORT len = *(USHORT*)(e + 0x58);
        PWCH   buf = *(PWCH*)(e + 0x60);
        if (len != 0 && buf != NULL)
        {
            UNICODE_STRING u;
            u.Buffer = buf; u.Length = len; u.MaximumLength = len;
            if (RtlEqualUnicodeString(&u, &want, TRUE))
            {
                base = *(ULONG64*)(e + 0x30);
                size = *(ULONG*)(e + 0x40);
                break;
            }
        }
    }
    KLogF("[ntdump] ntoskrnl base=0x%llX size=0x%X\n", base, size);
    if (base == 0 || size == 0 || size > 0x4000000) return;

    {
        UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
        PCHAR chunk;
        ULONG off = 0, written = 0;

        chunk = (PCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, 'pmiK');
        if (chunk == NULL) { KLog("[ntdump] pool alloc failed\n"); return; }

        RtlInitUnicodeString(&p, OUT_FILE);
        InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        if (!NT_SUCCESS(ZwCreateFile(&h, GENERIC_WRITE | SYNCHRONIZE, &oa, &io, NULL,
                                     FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                                     FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
        { KLog("[ntdump] create out file failed\n"); return; }

        while (off < size)
        {
            ULONG n = min(size - off, 0x10000);
            PUCHAR src = (PUCHAR)(ULONG_PTR)(base + off);
            if (!MmIsAddressValid(src)) { KLogF("[ntdump] invalid page at 0x%X\n", off); break; }
            RtlCopyMemory(chunk, src, n);
            ZwWriteFile(h, NULL, NULL, NULL, &io, chunk, n, NULL, NULL);
            off += n;
            written += n;
        }
        ZwClose(h);
        ExFreePoolWithTag(chunk, 'pmiK');
        KLogF("[ntdump] wrote %lu bytes\n", written);
    }
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl, ct, ct2;
    ULONG waited = 0, pid = 0, last = 0, stable = 0;
    UNREFERENCED_PARAMETER(ctx);
    ct.QuadPart = 0;
    KLog("[ntdump] waiter alive\n");
    for (;;)
    {
        pid = FindPid(L"r5apex_dx12.exe", &ct2);
        if (pid != 0 && pid == last && ct2.QuadPart == ct.QuadPart) stable += 500;
        else { last = pid; ct = ct2; stable = 0; }
        if (pid != 0 && stable >= (ULONG)SETTLE_SEC * 1000) break;
        dl.QuadPart = -5000000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &dl);
        waited += 500;
        if (waited > 1800000) { KLog("[ntdump] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); }
    }
    KLogF("[ntdump] game pid=%lu, dumping ntoskrnl...\n", pid);
    DumpNt();
    KLog("[ntdump] done\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h = NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    KLog("\n[ntdump] === entry ===\n");
    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, Waiter, NULL);
    if (NT_SUCCESS(st) && h != NULL) ZwClose(h);
    KLogF("[ntdump] thread=0x%X\n", st);
    { LARGE_INTEGER d; d.QuadPart = -30000000LL; KeDelayExecutionThread(KernelMode, FALSE, &d); }
    return STATUS_SUCCESS;
}

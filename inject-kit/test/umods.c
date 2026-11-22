// umods.sys -- 枚举游戏进程的 PEB->Ldr 模块列表，并把可疑模块 dump 出来
//   纯读取 + 文件写入；所有大缓冲区走池，避免内核栈溢出
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntimage.h>

#define LOG_FILE  L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define MOD_FILE  L"\\??\\C:\\ProgramData\\umods.txt"
#define SETTLE_SEC 20

NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSYSAPI BOOLEAN NTAPI MmIsAddressValid(PVOID);

typedef struct _SPI4
{
    ULONG Next; ULONG Threads; LARGE_INTEGER W; ULONG HF; ULONG HW;
    ULONGLONG CT; LARGE_INTEGER Cr; LARGE_INTEGER U; LARGE_INTEGER K;
    UNICODE_STRING ImageName; LONG BP; HANDLE PID;
} SPI4, *PSPI4;

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
      for (;;) {
          PSPI4 e = (PSPI4)p;
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

/* 把用户态镜像 dump 到文件 */
static VOID DumpUmod(ULONG64 base, ULONG size, PCSTR tag)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    WCHAR path[160]; PCHAR buf; ULONG off = 0;

    RtlStringCchPrintfW(path, RTL_NUMBER_OF(path), L"\\??\\C:\\ProgramData\\umod_%S.bin", tag);
    RtlInitUnicodeString(&p, path);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, GENERIC_WRITE | SYNCHRONIZE, &oa, &io, NULL,
                                 FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0))) return;

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
}

static VOID EnumModules(PEPROCESS proc)
{
    KAPC_STATE apc;
    PPEB peb;
    LIST_ENTRY* head;
    LIST_ENTRY* cur;
    ULONG count = 0;

    KeStackAttachProcess(proc, &apc);
    peb = (PPEB)PsGetProcessPeb(PsGetCurrentProcess());
    if (peb == NULL) { KeUnstackDetachProcess(&apc); KLog("[umods] no peb\n"); return; }

    {
        PVOID ldr = *(PVOID*)((PUCHAR)peb + 0x18);      /* PEB->Ldr 是指针 */
        if (ldr == NULL || (ULONG64)ldr < 0x10000 || (ULONG64)ldr > 0x00007FFFFFFFFFFFULL)
        {
            KeUnstackDetachProcess(&apc);
            KLogF("[umods] bad Ldr 0x%p\n", ldr);
            return;
        }
        head = (LIST_ENTRY*)((PUCHAR)ldr + 0x10);        /* InLoadOrderModuleList */
        KLogF("[umods] Ldr=0x%p list=0x%p\n", ldr, head);
    }

    for (cur = head->Flink; cur != head && cur != NULL; cur = cur->Flink)
    {
        PUCHAR e = (PUCHAR)cur;
        ULONG64 dllBase = *(ULONG64*)(e + 0x30);
        ULONG   sizeImg = *(ULONG*)(e + 0x40);
        UNICODE_STRING baseName;
        CHAR line[300];

        baseName.Length = *(USHORT*)(e + 0x58);
        baseName.MaximumLength = baseName.Length;
        baseName.Buffer = *(PWCH*)(e + 0x60);

        if (baseName.Buffer == NULL || baseName.Length == 0) continue;

        RtlStringCchPrintfA(line, RTL_NUMBER_OF(line), "%-40wZ base=0x%llX size=0x%X\n",
                            &baseName, dllBase, sizeImg);
        WriteA(MOD_FILE, line, (ULONG)strlen(line));
        count++;

        /* 可疑：名字里含 ea/javelin/r5ac/anticheat 等特征 */
        {
            CHAR low[128];
            ULONG i;

            RtlStringCchPrintfA(low, RTL_NUMBER_OF(low), "%wZ", &baseName);
            for (i = 0; low[i] != 0; i++)
                if (low[i] >= 'A' && low[i] <= 'Z') low[i] = (CHAR)(low[i] + 32);

            if (strstr(low, "ea") || strstr(low, "javelin") || strstr(low, "anticheat") ||
                strstr(low, "r5") || strstr(low, "ac_"))
            {
                CHAR fname[96];
                RtlStringCchPrintfA(fname, RTL_NUMBER_OF(fname), "%llX_%s", dllBase, low);
                for (i = 0; fname[i] != 0; i++)
                    if (fname[i] == '.' || fname[i] == '\\' || fname[i] == '/') fname[i] = '_';
                KLogF("[umods] SUSPECT %s base=0x%llX size=0x%X\n", low, dllBase, sizeImg);
                if (sizeImg > 0x1000 && sizeImg < 0x4000000)
                    DumpUmod(dllBase, sizeImg, fname);
            }
        }
        if (count > 400) break;
    }
    KeUnstackDetachProcess(&apc);
    KLogF("[umods] total modules=%lu\n", count);
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl, ct, ct2;
    ULONG waited = 0, pid = 0, last = 0, stable = 0;
    NTSTATUS st;
    PEPROCESS proc = NULL;
    UNREFERENCED_PARAMETER(ctx);
    ct.QuadPart = 0;
    KLog("[umods] waiter alive\n");
    for (;;)
    {
        pid = FindPid(L"r5apex_dx12.exe", &ct2);
        if (pid != 0 && pid == last && ct2.QuadPart == ct.QuadPart) stable += 500;
        else { last = pid; ct = ct2; stable = 0; }
        if (pid != 0 && stable >= (ULONG)SETTLE_SEC * 1000) break;
        dl.QuadPart = -5000000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &dl);
        waited += 500;
        if (waited > 1800000) { KLog("[umods] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); }
    }
    KLogF("[umods] game pid=%lu\n", pid);
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    if (!NT_SUCCESS(st)) { KLogF("[umods] lookup=0x%X\n", st); PsTerminateSystemThread(st); }
    EnumModules(proc);
    ObDereferenceObject(proc);
    KLog("[umods] done\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h = NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    KLog("\n[umods] === entry ===\n");
    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, Waiter, NULL);
    if (NT_SUCCESS(st) && h != NULL) ZwClose(h);
    KLogF("[umods] thread=0x%X\n", st);
    { LARGE_INTEGER d; d.QuadPart = -30000000LL; KeDelayExecutionThread(KernelMode, FALSE, &d); }
    return STATUS_SUCCESS;
}

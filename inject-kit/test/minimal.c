// minimal.c -- 最小驱动：只返回成功，用来判断 kdmapper/iqvw64e 本身是否可用
#include <ntifs.h>

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[minimal] entry ok\n");
    return STATUS_SUCCESS;
}

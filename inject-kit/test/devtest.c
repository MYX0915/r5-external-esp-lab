// devtest.c -- 只做 IoCreateDevice + IoCreateSymbolicLink，用来隔离 kdmapper 下的崩溃点
#include <ntifs.h>

#define DT_DEV  L"\\Device\\DevTest"
#define DT_LINK L"\\DosDevices\\DevTest"

static PDEVICE_OBJECT g_dev = NULL;

static NTSTATUS DtCreateClose(PDEVICE_OBJECT d, PIRP irp)
{
    UNREFERENCED_PARAMETER(d);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING devName, linkName;
    NTSTATUS st;
    ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[devtest] entry\n");

    RtlInitUnicodeString(&devName, DT_DEV);
    st = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
                        FILE_DEVICE_SECURE_OPEN, FALSE, &g_dev);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[devtest] IoCreateDevice=0x%X\n", st);
    if (!NT_SUCCESS(st)) return st;

    RtlInitUnicodeString(&linkName, DT_LINK);
    st = IoCreateSymbolicLink(&linkName, &devName);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[devtest] IoCreateSymbolicLink=0x%X\n", st);

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = DtCreateClose;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[devtest] major set\n");

    g_dev->Flags &= ~DO_DEVICE_INITIALIZING;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[devtest] done\n");
    return STATUS_SUCCESS;
}

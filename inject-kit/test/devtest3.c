// devtest3.c -- entry 璧风嚎绋嬶紱绾跨▼绔嬪埢寤鸿澶?+ 绗﹀彿閾炬帴锛涚敤鎴锋€佺洿鎺ュ紑 \\.\DevTest3
#include <ntifs.h>

#define D3_DEV  L"\\Device\\DevTest3"
#define D3_LINK L"\\DosDevices\\DevTest3"

static PDEVICE_OBJECT   g_dev = NULL;
static PDRIVER_OBJECT   g_drv = NULL;
static volatile LONG    g_stage = 0;

static NTSTATUS D3CreateClose(PDEVICE_OBJECT d, PIRP irp)
{
    UNREFERENCED_PARAMETER(d);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static VOID D3Worker(PVOID ctx)
{
    UNICODE_STRING devName, linkName;
    NTSTATUS st;

    UNREFERENCED_PARAMETER(ctx);
    InterlockedExchange(&g_stage, 1);

    RtlInitUnicodeString(&devName, D3_DEV);
    st = IoCreateDevice(g_drv, 0, &devName, FILE_DEVICE_UNKNOWN,
                        FILE_DEVICE_SECURE_OPEN, FALSE, &g_dev);
    InterlockedExchange(&g_stage, 2);
    if (NT_SUCCESS(st)) {
        ULONG i;
        RtlInitUnicodeString(&linkName, D3_LINK);
        IoCreateSymbolicLink(&linkName, &devName);
        for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
            g_drv->MajorFunction[i] = D3CreateClose;
        g_dev->Flags &= ~DO_DEVICE_INITIALIZING;
        InterlockedExchange(&g_stage, 3);
    } else {
        InterlockedExchange(&g_stage, 100 + (LONG)(st & 0xFF));
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    HANDLE h = NULL;
    NTSTATUS st;

    UNREFERENCED_PARAMETER(RegistryPath);
    g_drv = DriverObject;
    InterlockedExchange(&g_stage, 0);

    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, D3Worker, NULL);
    if (NT_SUCCESS(st)) {
        InterlockedExchange(&g_stage, 10);
        if (h) ZwClose(h);
    } else {
        InterlockedExchange(&g_stage, 200 + (LONG)(st & 0xFF));
    }
    return STATUS_SUCCESS;
}


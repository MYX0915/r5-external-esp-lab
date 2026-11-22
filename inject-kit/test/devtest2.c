// devtest2.c -- 分阶段：entry 只起线程；线程先建命名事件，再建设备
// 用户态可先探测 \BaseNamedObjects\KmapProbeEvt 是否存在，随后再看 \\.\DevTest
#include <ntifs.h>

#define DT2_DEV  L"\\Device\\DevTest2"
#define DT2_LINK L"\\DosDevices\\DevTest2"
#define DT2_EVT  L"\\BaseNamedObjects\\KmapProbeEvt"

static PDEVICE_OBJECT g_dev = NULL;
static PKEVENT        g_evt = NULL;

static VOID WorkerThread(PVOID ctx)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES oa;
    LARGE_INTEGER delay;
    NTSTATUS st;

    UNREFERENCED_PARAMETER(ctx);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[devtest2] worker start\n");

    /* 1s 后建命名事件（用户态可 OpenEvent 探测） */
    delay.QuadPart = -10000000LL;                  // 1s
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    RtlInitUnicodeString(&name, DT2_EVT);
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateEvent(&g_evt, EVENT_ALL_ACCESS, &oa, NotificationEvent, FALSE);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[devtest2] create event=0x%X\n", st);

    /* 再等 2s，然后才建设备对象 */
    delay.QuadPart = -20000000LL;
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    {
        UNICODE_STRING devName, linkName;
        PDRIVER_OBJECT drv = NULL;

        RtlInitUnicodeString(&devName, DT2_DEV);
        /* 用 DriverObject：从当前驱动对象取（映射驱动可能为 NULL，故先判空） */
        drv = (PDRIVER_OBJECT)ctx;
        if (drv) {
            st = IoCreateDevice(drv, 0, &devName, FILE_DEVICE_UNKNOWN,
                                FILE_DEVICE_SECURE_OPEN, FALSE, &g_dev);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[devtest2] IoCreateDevice=0x%X\n", st);
            if (NT_SUCCESS(st)) {
                RtlInitUnicodeString(&linkName, DT2_LINK);
                st = IoCreateSymbolicLink(&linkName, &devName);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[devtest2] symlink=0x%X\n", st);
            }
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[devtest2] no driver object\n");
        }
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    HANDLE hThread = NULL;
    NTSTATUS st;

    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[devtest2] entry\n");
    st = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL,
                              WorkerThread, DriverObject);
    if (NT_SUCCESS(st) && hThread) ZwClose(hThread);
    return STATUS_SUCCESS;
}

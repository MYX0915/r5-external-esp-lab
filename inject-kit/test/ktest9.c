// ktest9.c -- 分配矩阵探针：在目标进程里跑 5 种分配/改保护组合，并与 explorer.exe 对照
// 结果写 C:\ProgramData\kmaplog.txt
#include <ntifs.h>
#include <ntstrsafe.h>

#define LOG_FILE L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define SETTLE_SEC 42

NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

typedef struct _SPI_HEAD
{
    ULONG NextEntryOffset; ULONG NumberOfThreads; LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount; ULONG NumberOfThreadsHighWatermark; ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime, UserTime, KernelTime; UNICODE_STRING ImageName;
    LONG BasePriority; HANDLE UniqueProcessId;
} SPI_HEAD, *PSPI_HEAD;

static VOID KLog(PCSTR t)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h; size_t n=0;
    RtlInitUnicodeString(&p, LOG_FILE);
    InitializeObjectAttributes(&oa,&p,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,NULL,NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, FILE_APPEND_DATA|SYNCHRONIZE,&oa,&io,NULL,FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0))) return;
    RtlStringCchLengthA(t,2048,&n);
    ZwWriteFile(h,NULL,NULL,NULL,&io,(PVOID)t,(ULONG)n,NULL,NULL);
    ZwFlushBuffersFile(h,&io); ZwClose(h);
}
static VOID KLogF(PCSTR f,...)
{ CHAR b[512]; va_list ap; va_start(ap,f); RtlStringCchVPrintfA(b,sizeof(b),f,ap); va_end(ap); KLog(b); }

static ULONG FindPid(PCWSTR name, LARGE_INTEGER* outCreate)
{
    ULONG size=1<<20, ret=0; PVOID buf; NTSTATUS st; UNICODE_STRING want;
    buf=ExAllocatePool2(POOL_FLAG_NON_PAGED,size,'pmiK'); if(!buf) return 0;
    st=ZwQuerySystemInformation(5,buf,size,&ret);
    if (st==STATUS_INFO_LENGTH_MISMATCH && ret>size){ ExFreePoolWithTag(buf,'pmiK'); size=ret+0x1000;
        buf=ExAllocatePool2(POOL_FLAG_NON_PAGED,size,'pmiK'); if(!buf) return 0;
        st=ZwQuerySystemInformation(5,buf,size,&ret); }
    if(!NT_SUCCESS(st)){ ExFreePoolWithTag(buf,'pmiK'); return 0; }
    RtlInitUnicodeString(&want,name);
    { PUCHAR p=(PUCHAR)buf;
      for(;;){ PSPI_HEAD e=(PSPI_HEAD)p;
        if(e->ImageName.Buffer&&e->ImageName.Length){ UNICODE_STRING u;
            u.Buffer=e->ImageName.Buffer; u.Length=e->ImageName.Length; u.MaximumLength=e->ImageName.Length;
            if(RtlEqualUnicodeString(&u,&want,TRUE)){ if(outCreate)*outCreate=e->CreateTime;
                ExFreePoolWithTag(buf,'pmiK'); return (ULONG)(ULONG_PTR)e->UniqueProcessId; } }
        if(!e->NextEntryOffset) break; p+=e->NextEntryOffset; } }
    ExFreePoolWithTag(buf,'pmiK'); return 0;
}

/* 在 proc 里跑矩阵测试 */
static VOID RunMatrix(PEPROCESS proc, PCSTR tag)
{
    KAPC_STATE apc; NTSTATUS st; PVOID va; SIZE_T sz; ULONG oldp;

    KLogF("[ktest9] ===== matrix on %s =====\n", tag);
    KeStackAttachProcess(proc, &apc);

    /* 1) 直接 RWX */
    va=NULL; sz=0x1000;
    st=ZwAllocateVirtualMemory(NtCurrentProcess(),&va,0,&sz,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    KLogF("[ktest9] 1 RWX alloc            st=0x%X va=%p\n", st, va);

    /* 2) 直接 RX */
    va=NULL; sz=0x1000;
    st=ZwAllocateVirtualMemory(NtCurrentProcess(),&va,0,&sz,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READ);
    KLogF("[ktest9] 2 RX  alloc            st=0x%X va=%p\n", st, va);

    /* 3) RW -> RX */
    va=NULL; sz=0x1000;
    st=ZwAllocateVirtualMemory(NtCurrentProcess(),&va,0,&sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (NT_SUCCESS(st)) {
        PVOID b=va; SIZE_T r=sz; oldp=0;
        NTSTATUS p1=ZwProtectVirtualMemory(NtCurrentProcess(),&b,&r,PAGE_EXECUTE_READ,&oldp);
        KLogF("[ktest9] 3 RW->RX protect       st=0x%X va=%p\n", p1, va);
    } else KLogF("[ktest9] 3 RW alloc failed 0x%X\n", st);

    /* 4) RW -> R（对照：非可执行改保护是否也被拒） */
    va=NULL; sz=0x1000;
    st=ZwAllocateVirtualMemory(NtCurrentProcess(),&va,0,&sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (NT_SUCCESS(st)) {
        PVOID b=va; SIZE_T r=sz; oldp=0;
        NTSTATUS p1=ZwProtectVirtualMemory(NtCurrentProcess(),&b,&r,PAGE_READONLY,&oldp);
        KLogF("[ktest9] 4 RW->R  protect       st=0x%X va=%p\n", p1, va);
    } else KLogF("[ktest9] 4 RW alloc failed 0x%X\n", st);

    /* 5) 先 RESERVE 再 COMMIT(RWX) */
    va=NULL; sz=0x1000;
    st=ZwAllocateVirtualMemory(NtCurrentProcess(),&va,0,&sz,MEM_RESERVE,PAGE_NOACCESS);
    if (NT_SUCCESS(st)) {
        SIZE_T s2=0x1000;
        NTSTATUS c=ZwAllocateVirtualMemory(NtCurrentProcess(),&va,0,&s2,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
        KLogF("[ktest9] 5 reserve+commit RWX   st=0x%X va=%p\n", c, va);
    } else KLogF("[ktest9] 5 reserve failed 0x%X\n", st);

    KeUnstackDetachProcess(&apc);
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl, ct, ct2; ULONG waited=0, pid=0, last=0, stable=0;
    PEPROCESS proc=NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(ctx);

    KLog("[ktest9] waiter alive\n");
    for(;;){
        pid=FindPid(L"r5apex_dx12.exe",&ct2);
        if(pid&&pid==last&&ct2.QuadPart==ct.QuadPart) stable+=500;
        else { last=pid; ct=ct2; stable=0; }
        if(pid&&stable>=(ULONG)SETTLE_SEC*1000) break;
        dl.QuadPart=-5000000LL; KeDelayExecutionThread(KernelMode,FALSE,&dl);
        waited+=500; if(waited>1800000) PsTerminateSystemThread(STATUS_TIMEOUT);
    }
    KLogF("[ktest9] target pid=%lu\n", pid);

    st=PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid,&proc);
    if(NT_SUCCESS(st)){ RunMatrix(proc,"r5apex_dx12"); ObDereferenceObject(proc); }
    else KLogF("[ktest9] lookup=0x%X\n", st);

    /* 对照组：explorer.exe */
    { ULONG e=FindPid(L"explorer.exe", &ct2); PEPROCESS ep=NULL;
      if(e && NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)e,&ep))){
          RunMatrix(ep,"explorer"); ObDereferenceObject(ep);
      } else KLog("[ktest9] explorer not found\n"); }

    KLog("[ktest9] done\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h=NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    KLog("\n[ktest9] === entry ===\n");
    st=PsCreateSystemThread(&h,THREAD_ALL_ACCESS,NULL,NULL,NULL,Waiter,NULL);
    if(NT_SUCCESS(st)&&h) ZwClose(h);
    KLogF("[ktest9] thread=0x%X\n", st);
    { LARGE_INTEGER d; d.QuadPart=-30000000LL; KeDelayExecutionThread(KernelMode,FALSE,&d); }
    return STATUS_SUCCESS;
}

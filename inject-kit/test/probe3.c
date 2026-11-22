// probe3.sys -- 判别：线程是否真的被创建（用 Sleep 作起始地址，看线程数是否变化）
#include <ntifs.h>
#include <ntstrsafe.h>

#define LOG_FILE L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define SETTLE_SEC 32
NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI RtlCreateUserThread(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PVOID);

typedef struct _SPIC { ULONG Next; ULONG Threads; LARGE_INTEGER W; ULONG HF; ULONG HW;
    ULONGLONG CT; LARGE_INTEGER Cr; LARGE_INTEGER U; LARGE_INTEGER K; UNICODE_STRING ImageName;
    LONG BP; HANDLE PID; } SPIC, *PSPIC;

static VOID WA(PCWSTR f2, PCSTR t, ULONG len){ UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    RtlInitUnicodeString(&p,f2); InitializeObjectAttributes(&oa,&p,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,NULL,NULL);
    if(!NT_SUCCESS(ZwCreateFile(&h,FILE_APPEND_DATA|SYNCHRONIZE,&oa,&io,NULL,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ,FILE_OPEN_IF,FILE_SYNCHRONOUS_IO_NONALERT,NULL,0))) return;
    ZwWriteFile(h,NULL,NULL,NULL,&io,(PVOID)t,len,NULL,NULL); ZwFlushBuffersFile(h,&io); ZwClose(h); }
static VOID K(PCSTR t){ size_t n=0; RtlStringCchLengthA(t,2048,&n); WA(LOG_FILE,t,(ULONG)n); }
static VOID KF(PCSTR f,...){ CHAR b[400]; va_list ap; va_start(ap,f); RtlStringCchVPrintfA(b,sizeof(b),f,ap); va_end(ap); K(b); }

static ULONG Threads(ULONG want)
{
    ULONG size=1<<20,ret=0; PVOID buf; NTSTATUS st;
    buf=ExAllocatePool2(POOL_FLAG_NON_PAGED,size,'pmiK'); if(!buf) return 0;
    st=ZwQuerySystemInformation(5,buf,size,&ret);
    if(st==STATUS_INFO_LENGTH_MISMATCH&&ret>size){ ExFreePoolWithTag(buf,'pmiK'); size=ret+0x1000;
        buf=ExAllocatePool2(POOL_FLAG_NON_PAGED,size,'pmiK'); if(!buf) return 0;
        st=ZwQuerySystemInformation(5,buf,size,&ret); }
    if(!NT_SUCCESS(st)){ ExFreePoolWithTag(buf,'pmiK'); return 0; }
    { PUCHAR p=(PUCHAR)buf; ULONG n=0;
      for(;;){ PSPIC e=(PSPIC)p;
        if((ULONG)(ULONG_PTR)e->PID==want){ n=e->Threads; break; }
        if(!e->Next) break; p+=e->Next; }
      ExFreePoolWithTag(buf,'pmiK'); return n; }
}
static ULONG FindPid(PCWSTR name, LARGE_INTEGER* oc)
{
    ULONG size=1<<20,ret=0,res=0; PVOID buf; NTSTATUS st; UNICODE_STRING want;
    buf=ExAllocatePool2(POOL_FLAG_NON_PAGED,size,'pmiK'); if(!buf) return 0;
    st=ZwQuerySystemInformation(5,buf,size,&ret);
    if(st==STATUS_INFO_LENGTH_MISMATCH&&ret>size){ ExFreePoolWithTag(buf,'pmiK'); size=ret+0x1000;
        buf=ExAllocatePool2(POOL_FLAG_NON_PAGED,size,'pmiK'); if(!buf) return 0;
        st=ZwQuerySystemInformation(5,buf,size,&ret); }
    if(!NT_SUCCESS(st)){ ExFreePoolWithTag(buf,'pmiK'); return 0; }
    RtlInitUnicodeString(&want,name);
    { PUCHAR p=(PUCHAR)buf;
      for(;;){ PSPIC e=(PSPIC)p;
        if(e->ImageName.Buffer&&e->ImageName.Length){ UNICODE_STRING u=e->ImageName;
            if(RtlEqualUnicodeString(&u,&want,TRUE)){ res=(ULONG)(ULONG_PTR)e->PID; if(oc)*oc=e->Cr; break; } }
        if(!e->Next) break; p+=e->Next; } }
    ExFreePoolWithTag(buf,'pmiK'); return res;
}
static ULONG64 FindMod(PCWSTR want)
{
    PPEB peb=(PPEB)PsGetProcessPeb(PsGetCurrentProcess()); PVOID ldr; LIST_ENTRY* head; LIST_ENTRY* cur; UNICODE_STRING w;
    if(!peb) return 0; ldr=*(PVOID*)((PUCHAR)peb+0x18); if(!ldr) return 0;
    head=(LIST_ENTRY*)((PUCHAR)ldr+0x10); RtlInitUnicodeString(&w,want);
    for(cur=head->Flink;cur!=head&&cur;cur=cur->Flink){ PUCHAR e=(PUCHAR)cur; UNICODE_STRING bn;
        bn.Length=*(USHORT*)(e+0x58); bn.MaximumLength=bn.Length; bn.Buffer=*(PWCH*)(e+0x60);
        if(bn.Buffer&&bn.Length&&RtlEqualUnicodeString(&bn,&w,TRUE)) return *(ULONG64*)(e+0x30); }
    return 0;
}

static VOID Test(PEPROCESS proc, ULONG pid)
{
    KAPC_STATE apc; ULONG64 k32, sleepfn; NTSTATUS st; HANDLE th=NULL;
    ULONG t0,t1,t2;

    t0 = Threads(pid);
    KeStackAttachProcess(proc,&apc);
    k32 = FindMod(L"kernel32.dll");
    sleepfn = k32 ? (k32 + 0x44DD0) : 0;    /* Sleep 的 RVA 后面用导出名兜底 */
    KF("[probe3] k32=0x%llX sleep=0x%llX\n", k32, sleepfn);
    st = RtlCreateUserThread(NtCurrentProcess(), NULL, FALSE, 0, 0, 0, (PVOID)(ULONG_PTR)sleepfn, (PVOID)(ULONG_PTR)10000, &th, NULL);
    KF("[probe3] create st=0x%X\n", st);
    if (th) ZwClose(th);
    KeUnstackDetachProcess(&apc);

    { LARGE_INTEGER d; d.QuadPart=-10000000LL; KeDelayExecutionThread(KernelMode,FALSE,&d); }
    t1 = Threads(pid);
    KF("[probe3] threads before=%lu after=%lu\n", t0, t1);
    { LARGE_INTEGER d; d.QuadPart=-120000000LL; KeDelayExecutionThread(KernelMode,FALSE,&d); }
    t2 = Threads(pid);
    KF("[probe3] threads later=%lu\n", t2);
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl,ct,ct2; ULONG waited=0,pid=0,last=0,stable=0; PEPROCESS proc=NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(ctx); ct.QuadPart=0; K("[probe3] waiter alive\n");
    for(;;){ pid=FindPid(L"r5apex_dx12.exe",&ct2);
        if(pid&&pid==last&&ct2.QuadPart==ct.QuadPart) stable+=500; else { last=pid; ct=ct2; stable=0; }
        if(pid&&stable>=(ULONG)SETTLE_SEC*1000) break;
        dl.QuadPart=-5000000LL; KeDelayExecutionThread(KernelMode,FALSE,&dl); waited+=500;
        if(waited>1800000){ K("[probe3] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); } }
    KF("[probe3] game pid=%lu\n", pid);
    st=PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid,&proc);
    if(!NT_SUCCESS(st)){ KF("[probe3] lookup=0x%X\n",st); PsTerminateSystemThread(st); }
    Test(proc,pid); ObDereferenceObject(proc);
    K("[probe3] done\n"); PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h=NULL; NTSTATUS st; UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    K("\n[probe3] === entry ===\n");
    st=PsCreateSystemThread(&h,THREAD_ALL_ACCESS,NULL,NULL,NULL,Waiter,NULL);
    if(NT_SUCCESS(st)&&h) ZwClose(h);
    { LARGE_INTEGER d; d.QuadPart=-30000000LL; KeDelayExecutionThread(KernelMode,FALSE,&d); }
    return STATUS_SUCCESS;
}

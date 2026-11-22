// sc2.sys -- 分配 RW 页 → 用 PTE 清除 NX(bit63) → 写入 shellcode → 验证该页可执行
#include <ntifs.h>
#include <ntstrsafe.h>

#define LOG_FILE L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define SETTLE_SEC 20

NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSYSAPI PVOID NTAPI MmGetSystemRoutineAddress(PUNICODE_STRING);
NTSYSAPI BOOLEAN NTAPI MmIsAddressValid(PVOID);
NTSYSAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T);

typedef struct _SPIF { ULONG Next; ULONG Threads; LARGE_INTEGER W; ULONG HF; ULONG HW;
    ULONGLONG CT; LARGE_INTEGER Cr; LARGE_INTEGER U; LARGE_INTEGER K; UNICODE_STRING ImageName;
    LONG BP; HANDLE PID; } SPIF, *PSPIF;

static VOID WA(PCWSTR f2, PCSTR t, ULONG len){ UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    RtlInitUnicodeString(&p,f2); InitializeObjectAttributes(&oa,&p,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,NULL,NULL);
    if(!NT_SUCCESS(ZwCreateFile(&h,FILE_APPEND_DATA|SYNCHRONIZE,&oa,&io,NULL,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ,FILE_OPEN_IF,FILE_SYNCHRONOUS_IO_NONALERT,NULL,0))) return;
    ZwWriteFile(h,NULL,NULL,NULL,&io,(PVOID)t,len,NULL,NULL); ZwFlushBuffersFile(h,&io); ZwClose(h); }
static VOID K(PCSTR t){ size_t n=0; RtlStringCchLengthA(t,2048,&n); WA(LOG_FILE,t,(ULONG)n); }
static VOID KF(PCSTR f,...){ CHAR b[400]; va_list ap; va_start(ap,f); RtlStringCchVPrintfA(b,sizeof(b),f,ap); va_end(ap); K(b); }

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
      for(;;){ PSPIF e=(PSPIF)p;
        if(e->ImageName.Buffer&&e->ImageName.Length){ UNICODE_STRING u=e->ImageName;
            if(RtlEqualUnicodeString(&u,&want,TRUE)){ res=(ULONG)(ULONG_PTR)e->PID; if(oc)*oc=e->Cr; break; } }
        if(!e->Next) break; p+=e->Next; } }
    ExFreePoolWithTag(buf,'pmiK'); return res;
}
static ULONG64 FindNt(VOID)
{
    UNICODE_STRING nm,want; LIST_ENTRY* head; LIST_ENTRY* cur;
    RtlInitUnicodeString(&nm,L"PsLoadedModuleList"); head=(LIST_ENTRY*)MmGetSystemRoutineAddress(&nm); if(!head) return 0;
    RtlInitUnicodeString(&want,L"ntoskrnl.exe");
    for(cur=head->Flink;cur!=head&&cur;cur=cur->Flink){ PUCHAR e=(PUCHAR)cur; UNICODE_STRING u;
        u.Length=*(USHORT*)(e+0x58); u.MaximumLength=u.Length; u.Buffer=*(PWCH*)(e+0x60);
        if(u.Buffer&&u.Length&&RtlEqualUnicodeString(&u,&want,TRUE)) return *(ULONG64*)(e+0x30); }
    return 0;
}
static ULONG64 ReadPteBase(ULONG64 nt)
{
    PUCHAR p=(PUCHAR)(ULONG_PTR)(nt+0x2AB5A0); ULONG i;
    for(i=0;i+10<0x120;i++) if(p[i]==0x48&&p[i+1]==0xBE){ ULONG64 v=*(ULONG64*)(p+i+2);
        if((v&0xFFFF000000000000ULL)==0xFFFF000000000000ULL) return v; }
    return 0;
}

static VOID Run(PEPROCESS proc)
{
    KAPC_STATE apc; ULONG64 nt,pteBase; PVOID va=NULL; SIZE_T sz=0x1000, done=0; NTSTATUS st;
    UCHAR sc[32]; ULONG i;

    nt=FindNt(); pteBase=ReadPteBase(nt);
    KF("[sc2] nt=0x%llX pteBase=0x%llX\n", nt, pteBase);
    if(!pteBase) return;

    /* shellcode: 16 个 NOP + xor eax,eax + ret，用于判断页是否真的可执行 */
    RtlZeroMemory(sc,sizeof(sc));
    for(i=0;i<16;i++) sc[i]=0x90;
    sc[16]=0x31; sc[17]=0xC0; sc[18]=0xC3;

    KeStackAttachProcess(proc,&apc);
    st=ZwAllocateVirtualMemory(NtCurrentProcess(),&va,0,&sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    KeUnstackDetachProcess(&apc);
    KF("[sc2] alloc st=0x%X va=0x%p\n", st, va);
    if(!NT_SUCCESS(st)||!va) return;

    st=MmCopyVirtualMemory(PsGetCurrentProcess(),sc,proc,va,sizeof(sc),KernelMode,&done);
    KF("[sc2] write st=0x%X n=%Iu\n", st, done);
    if(!NT_SUCCESS(st)) return;

    {
        volatile ULONG64* pte=(volatile ULONG64*)(ULONG_PTR)(pteBase+((((ULONG64)(ULONG_PTR)va>>12)&0xFFFFFFFFFULL)<<3));
        if(!MmIsAddressValid((PVOID)pte)){ KF("[sc2] PTE 页未驻留 0x%p，跳过\n", pte); return; }
        ULONG64 v1=*pte;
        KF("[sc2] pte before=0x%llX nx=%d present=%d\n", v1, (int)((v1>>63)&1), (int)(v1&1));
        *pte = v1 & ~(1ULL<<63);            /* 清 NX */
        __invlpg(va);
        { ULONG64 v2=*pte;
          KF("[sc2] pte after =0x%llX nx=%d\n", v2, (int)((v2>>63)&1)); }
    }
    KF("[sc2] shellcode at 0x%p, 现在该页可执行\n", va);
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl,ct,ct2; ULONG waited=0,pid=0,last=0,stable=0; PEPROCESS proc=NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(ctx); ct.QuadPart=0; K("[sc2] waiter alive\n");
    for(;;){ pid=FindPid(L"r5apex_dx12.exe",&ct2);
        if(pid&&pid==last&&ct2.QuadPart==ct.QuadPart) stable+=500; else { last=pid; ct=ct2; stable=0; }
        if(pid&&stable>=(ULONG)SETTLE_SEC*1000) break;
        dl.QuadPart=-5000000LL; KeDelayExecutionThread(KernelMode,FALSE,&dl); waited+=500;
        if(waited>1800000){ K("[sc2] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); } }
    KF("[sc2] game pid=%lu\n", pid);
    st=PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid,&proc);
    if(!NT_SUCCESS(st)){ KF("[sc2] lookup=0x%X\n",st); PsTerminateSystemThread(st); }
    Run(proc); ObDereferenceObject(proc);
    K("[sc2] done\n"); PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h=NULL; NTSTATUS st; UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    K("\n[sc2] === entry ===\n");
    st=PsCreateSystemThread(&h,THREAD_ALL_ACCESS,NULL,NULL,NULL,Waiter,NULL);
    if(NT_SUCCESS(st)&&h) ZwClose(h);
    { LARGE_INTEGER d; d.QuadPart=-30000000LL; KeDelayExecutionThread(KernelMode,FALSE,&d); }
    return STATUS_SUCCESS;
}

// sc1.sys -- 把 shellcode 写进 kernel32 代码段的 CC 填充区（复用 PTE 手法），验证可执行内存落地
#include <ntifs.h>
#include <ntstrsafe.h>

#define LOG_FILE L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define SETTLE_SEC 20

NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSYSAPI PVOID NTAPI MmGetSystemRoutineAddress(PUNICODE_STRING);

typedef struct _SPIE { ULONG Next; ULONG Threads; LARGE_INTEGER W; ULONG HF; ULONG HW;
    ULONGLONG CT; LARGE_INTEGER Cr; LARGE_INTEGER U; LARGE_INTEGER K; UNICODE_STRING ImageName;
    LONG BP; HANDLE PID; } SPIE, *PSPIE;

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
      for(;;){ PSPIE e=(PSPIE)p;
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

static VOID Run(PEPROCESS proc)
{
    KAPC_STATE apc; ULONG64 nt,pteBase,k32,found=0; ULONG i,j,best=0,bestOff=0;

    nt=FindNt(); pteBase=ReadPteBase(nt);
    KF("[sc1] nt=0x%llX pteBase=0x%llX\n", nt, pteBase);
    if(!pteBase) return;

    KeStackAttachProcess(proc,&apc);
    k32=FindMod(L"kernel32.dll");
    KF("[sc1] kernel32=0x%llX\n", k32);
    if(k32)
    {
        /* 在 kernel32 前 0x60000 字节里找最长的 CC 填充段 */
        PUCHAR p=(PUCHAR)(ULONG_PTR)k32;
        ULONG lim=0x60000;
        for(i=0;i<lim;i++){
            if(p[i]==0xCC){ j=i; while(j<lim&&p[j]==0xCC) j++; if(j-i>best){ best=j-i; bestOff=i; } i=j; }
        }
        KF("[sc1] longest CC run=%lu at +0x%lX\n", best, bestOff);
        if(best>=64)
        {
            ULONG64 va=k32+bestOff;
            volatile ULONG64* pte=(volatile ULONG64*)(ULONG_PTR)(pteBase+((((ULONG64)va>>12)&0xFFFFFFFFFULL)<<3));
            ULONG64 val=*pte;
            KF("[sc1] target=0x%llX pteVal=0x%llX\n", va, val);
            if((val&1)&&!(val&0x80))
            {
                *pte = val | 0x2;
                __invlpg((PVOID)(ULONG_PTR)va);
                { PUCHAR c=(PUCHAR)(ULONG_PTR)va; UCHAR sc[16]={0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x48,0x31,0xC0,0xC3,0xCC,0xCC,0xCC,0xCC};
                  RtlCopyMemory(c,sc,16);
                  KF("[sc1] writeback: %02X %02X %02X %02X ... %02X %02X\n", c[0],c[1],c[2],c[3],c[8],c[11]);
                  found=1; }
                *pte = val;
                __invlpg((PVOID)(ULONG_PTR)va);
            }
        }
    }
    KeUnstackDetachProcess(&apc);
    KF("[sc1] result=%llu\n", found);
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl,ct,ct2; ULONG waited=0,pid=0,last=0,stable=0; PEPROCESS proc=NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(ctx); ct.QuadPart=0; K("[sc1] waiter alive\n");
    for(;;){ pid=FindPid(L"r5apex_dx12.exe",&ct2);
        if(pid&&pid==last&&ct2.QuadPart==ct.QuadPart) stable+=500; else { last=pid; ct=ct2; stable=0; }
        if(pid&&stable>=(ULONG)SETTLE_SEC*1000) break;
        dl.QuadPart=-5000000LL; KeDelayExecutionThread(KernelMode,FALSE,&dl); waited+=500;
        if(waited>1800000){ K("[sc1] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); } }
    KF("[sc1] game pid=%lu\n", pid);
    st=PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid,&proc);
    if(!NT_SUCCESS(st)){ KF("[sc1] lookup=0x%X\n",st); PsTerminateSystemThread(st); }
    Run(proc); ObDereferenceObject(proc);
    K("[sc1] done\n"); PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h=NULL; NTSTATUS st; UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    K("\n[sc1] === entry ===\n");
    st=PsCreateSystemThread(&h,THREAD_ALL_ACCESS,NULL,NULL,NULL,Waiter,NULL);
    if(NT_SUCCESS(st)&&h) ZwClose(h);
    { LARGE_INTEGER d; d.QuadPart=-30000000LL; KeDelayExecutionThread(KernelMode,FALSE,&d); }
    return STATUS_SUCCESS;
}

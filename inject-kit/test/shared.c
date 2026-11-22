// shared.sys -- read-only probe: is the ntdll code page of module+RVA the same
// physical frame in two different processes?  (no writes at all)
#include <ntifs.h>
#include <ntstrsafe.h>

#define LOG_FILE L"\\??\\C:\\ProgramData\\kmaplog.txt"

typedef unsigned __int64 U64;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
NTSYSAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T);
NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS);
NTSYSAPI BOOLEAN NTAPI MmIsAddressValid(PVOID);
NTSYSAPI PVOID NTAPI MmGetSystemRoutineAddress(PUNICODE_STRING);

typedef struct _SPIX { ULONG Next; ULONG Threads; LARGE_INTEGER W; ULONG HF; ULONG HW;
    ULONGLONG CT; LARGE_INTEGER Cr; LARGE_INTEGER U; LARGE_INTEGER K; UNICODE_STRING ImageName;
    LONG BP; HANDLE PID; } SPIX, *PSPIX;

static VOID WA(PCWSTR f2, PCSTR t, ULONG len){ UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    RtlInitUnicodeString(&p,f2); InitializeObjectAttributes(&oa,&p,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,NULL,NULL);
    if(!NT_SUCCESS(ZwCreateFile(&h,FILE_APPEND_DATA|SYNCHRONIZE,&oa,&io,NULL,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ,FILE_OPEN_IF,FILE_SYNCHRONOUS_IO_NONALERT,NULL,0))) return;
    ZwWriteFile(h,NULL,NULL,NULL,&io,(PVOID)t,len,NULL,NULL); ZwFlushBuffersFile(h,&io); ZwClose(h); }
static VOID K(PCSTR t){ size_t n=0; RtlStringCchLengthA(t,2048,&n); WA(LOG_FILE,t,(ULONG)n); }
static VOID KF(PCSTR f,...){ CHAR b[400]; va_list ap; va_start(ap,f); RtlStringCchVPrintfA(b,sizeof(b),f,ap); va_end(ap); K(b); }

static ULONG64 FindNt(VOID)
{
    UNICODE_STRING nm,want; LIST_ENTRY* head; LIST_ENTRY* cur;
    RtlInitUnicodeString(&nm,L"PsLoadedModuleList");
    head=(LIST_ENTRY*)MmGetSystemRoutineAddress(&nm); if(!head) return 0;
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
static ULONG64 ModBase(PEPROCESS proc, PCWSTR want)
{
    KAPC_STATE apc; PPEB peb; PVOID ldr; LIST_ENTRY* head; LIST_ENTRY* cur; ULONG64 res=0; UNICODE_STRING w;
    KeStackAttachProcess(proc,&apc);
    peb=(PPEB)PsGetProcessPeb(proc);
    if(peb){ ldr=*(PVOID*)((PUCHAR)peb+0x18);
        if(ldr){ head=(LIST_ENTRY*)((PUCHAR)ldr+0x10); RtlInitUnicodeString(&w,want);
            for(cur=head->Flink;cur!=head&&cur;cur=cur->Flink){ PUCHAR e=(PUCHAR)cur; UNICODE_STRING bn;
                bn.Length=*(USHORT*)(e+0x58); bn.MaximumLength=bn.Length; bn.Buffer=*(PWCH*)(e+0x60);
                if(bn.Buffer&&bn.Length&&RtlEqualUnicodeString(&bn,&w,TRUE)){ res=*(ULONG64*)(e+0x30); break; } } } }
    KeUnstackDetachProcess(&apc);
    return res;
}

static ULONG64 g_PteBase;

static BOOLEAN PfnOf(PEPROCESS proc, U64 va, U64* outPfn, U64* outPte)
{
    KAPC_STATE apc; U64 idx, pteAddr, val; BOOLEAN ok=FALSE;

    KeStackAttachProcess(proc,&apc);
    idx=(va>>12)&0xFFFFFFFFFULL;
    pteAddr=g_PteBase+(idx<<3);
    if(MmIsAddressValid((PVOID)(ULONG_PTR)pteAddr)){
        val=*(U64*)(ULONG_PTR)pteAddr;
        if(val&1){ *outPfn=(val>>12)&0xFFFFFFFFFULL; *outPte=val; ok=TRUE; }
    }
    KeUnstackDetachProcess(&apc);
    return ok;
}

static ULONG FindPid(PCWSTR name)
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
      for(;;){ PSPIX e=(PSPIX)p;
        if(e->ImageName.Buffer&&e->ImageName.Length){ UNICODE_STRING u=e->ImageName;
            if(RtlEqualUnicodeString(&u,&want,TRUE)){ res=(ULONG)(ULONG_PTR)e->PID; break; } }
        if(!e->Next) break; p+=e->Next; } }
    ExFreePoolWithTag(buf,'pmiK'); return res;
}

static VOID Run(VOID)
{
    ULONG pidA=0, pidB=0; PEPROCESS pa=NULL, pb=NULL; U64 nt;
    HANDLE hA=NULL, hB=NULL; NTSTATUS st;

    nt=FindNt(); g_PteBase=ReadPteBase(nt);
    KF("[shared] nt=0x%llX pteBase=0x%llX\n", nt, g_PteBase);
    if(!g_PteBase) return;

    pidA=FindPid(L"sc_target.exe");
    pidB=FindPid(L"notepad.exe");
    KF("[shared] pidA(sc_target)=%lu pidB(notepad)=%lu\n", pidA, pidB);
    if(!pidA||!pidB) { K("[shared] need one sc_target.exe and one notepad.exe\n"); return; }

    st=PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pidA,&pa);
    if(!NT_SUCCESS(st)) return;
    st=PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pidB,&pb);
    if(!NT_SUCCESS(st)){ ObDereferenceObject(pa); return; }

    {
        U64 vaA=ModBase(pa,L"ntdll.dll")+0x166A50;   /* NtDelayExecution */
        U64 vaB=ModBase(pb,L"ntdll.dll")+0x166A50;
        U64 pA=0,tA=0,pB=0,tB=0;

        if(PfnOf(pa,vaA,&pA,&tA)&&PfnOf(pb,vaB,&pB,&tB)){
            KF("[shared] vaA=0x%llX pte=0x%llX pfn=0x%llX\n", vaA, tA, pA);
            KF("[shared] vaB=0x%llX pte=0x%llX pfn=0x%llX\n", vaB, tB, pB);
            KF("[shared] SAME PHYSICAL PAGE = %s\n", (pA==pB) ? "YES" : "NO");
        } else {
            K("[shared] pfn read failed\n");
        }
    }

    ObDereferenceObject(pa); ObDereferenceObject(pb);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h=NULL; NTSTATUS st; UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    K("\n[shared] === entry ===\n");
    st=PsCreateSystemThread(&h,THREAD_ALL_ACCESS,NULL,NULL,NULL,(PKSTART_ROUTINE)Run,NULL);
    if(NT_SUCCESS(st)&&h) ZwClose(h);
    { LARGE_INTEGER d; d.QuadPart=-30000000LL; KeDelayExecutionThread(KernelMode,FALSE,&d); }
    return STATUS_SUCCESS;
}

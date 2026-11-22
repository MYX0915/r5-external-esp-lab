// probe2.sys -- 验证"影子地址空间"假设：分配 RW 页后检查其 PTE 是否真的存在
#include <ntifs.h>
#include <ntstrsafe.h>

#define LOG_FILE L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define SETTLE_SEC 20

NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
NTSYSAPI PVOID NTAPI MmGetSystemRoutineAddress(PUNICODE_STRING);

typedef struct _SPIA { ULONG Next; ULONG Threads; LARGE_INTEGER W; ULONG HF; ULONG HW;
    ULONGLONG CT; LARGE_INTEGER Cr; LARGE_INTEGER U; LARGE_INTEGER K; UNICODE_STRING ImageName;
    LONG BP; HANDLE PID; } SPIA, *PSPIA;

typedef struct _MBI2 { PVOID Base; PVOID AllocBase; ULONG AllocProt; ULONG P1; SIZE_T Size;
    ULONG State; ULONG Protect; ULONG Type; ULONG P2; } MBI2;

static VOID WA(PCWSTR file, PCSTR t, ULONG len)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    RtlInitUnicodeString(&p, file);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &io, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0))) return;
    ZwWriteFile(h, NULL, NULL, NULL, &io, (PVOID)t, len, NULL, NULL);
    ZwFlushBuffersFile(h, &io); ZwClose(h);
}
static VOID K(PCSTR t) { size_t n=0; RtlStringCchLengthA(t,2048,&n); WA(LOG_FILE,t,(ULONG)n); }
static VOID KF(PCSTR f, ...) { CHAR b[400]; va_list ap; va_start(ap,f); RtlStringCchVPrintfA(b,sizeof(b),f,ap); va_end(ap); K(b); }

static ULONG FindPid(PCWSTR name, LARGE_INTEGER* oc)
{
    ULONG size=1<<20, ret=0, res=0; PVOID buf; NTSTATUS st; UNICODE_STRING want;
    buf=ExAllocatePool2(POOL_FLAG_NON_PAGED,size,'pmiK'); if(!buf) return 0;
    st=ZwQuerySystemInformation(5,buf,size,&ret);
    if(st==STATUS_INFO_LENGTH_MISMATCH&&ret>size){ ExFreePoolWithTag(buf,'pmiK'); size=ret+0x1000;
        buf=ExAllocatePool2(POOL_FLAG_NON_PAGED,size,'pmiK'); if(!buf) return 0;
        st=ZwQuerySystemInformation(5,buf,size,&ret); }
    if(!NT_SUCCESS(st)){ ExFreePoolWithTag(buf,'pmiK'); return 0; }
    RtlInitUnicodeString(&want,name);
    { PUCHAR p=(PUCHAR)buf;
      for(;;){ PSPIA e=(PSPIA)p;
        if(e->ImageName.Buffer&&e->ImageName.Length){ UNICODE_STRING u=e->ImageName;
            if(RtlEqualUnicodeString(&u,&want,TRUE)){ res=(ULONG)(ULONG_PTR)e->PID; if(oc)*oc=e->Cr; break; } }
        if(!e->Next) break; p+=e->Next; } }
    ExFreePoolWithTag(buf,'pmiK');
    return res;
}

static ULONG64 FindNtBase(VOID)
{
    UNICODE_STRING nm, want; LIST_ENTRY* head; LIST_ENTRY* cur;
    RtlInitUnicodeString(&nm, L"PsLoadedModuleList");
    head=(LIST_ENTRY*)MmGetSystemRoutineAddress(&nm); if(!head) return 0;
    RtlInitUnicodeString(&want, L"ntoskrnl.exe");
    for(cur=head->Flink; cur!=head && cur; cur=cur->Flink){
        PUCHAR e=(PUCHAR)cur; UNICODE_STRING u;
        u.Length=*(USHORT*)(e+0x58); u.MaximumLength=u.Length; u.Buffer=*(PWCH*)(e+0x60);
        if(u.Buffer&&u.Length&&RtlEqualUnicodeString(&u,&want,TRUE)) return *(ULONG64*)(e+0x30);
    }
    return 0;
}

static ULONG64 ReadPteBase(ULONG64 ntBase)
{
    PUCHAR p=(PUCHAR)(ULONG_PTR)(ntBase+0x2AB5A0); ULONG i;
    for(i=0;i+10<0x120;i++)
        if(p[i]==0x48&&p[i+1]==0xBE){ ULONG64 v=*(ULONG64*)(p+i+2);
            if((v&0xFFFF000000000000ULL)==0xFFFF000000000000ULL) return v; }
    return 0;
}

static VOID Probe(PEPROCESS proc)
{
    KAPC_STATE apc; ULONG64 ntBase, pteBase, dirBase;
    PVOID va = NULL; SIZE_T sz = 0x1000; NTSTATUS st;

    ntBase = FindNtBase();
    pteBase = ReadPteBase(ntBase);
    dirBase = *(ULONG64*)((PUCHAR)proc + 0x28);
    KF("[probe2] nt=0x%llX pteBase=0x%llX dirBase=0x%llX\n", ntBase, pteBase, dirBase);
    if (pteBase == 0) { K("[probe2] pteBase 读取失败\n"); return; }

    KeStackAttachProcess(proc, &apc);

    /* 分配一块 RW */
    st = ZwAllocateVirtualMemory(NtCurrentProcess(), &va, 0, &sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    KF("[probe2] alloc RW st=0x%X va=0x%p\n", st, va);

    if (NT_SUCCESS(st) && va != NULL)
    {
        volatile ULONG64* pte;
        ULONG64 val;
        MBI2 mbi; SIZE_T r=0;

        pte = (volatile ULONG64*)(ULONG_PTR)(pteBase + ((((ULONG64)(ULONG_PTR)va >> 12) & 0xFFFFFFFFFULL) << 3));
        val = *pte;
        KF("[probe2] PTE@0x%p = 0x%llX  present=%d rw=%d\n", pte, val, (int)(val&1), (int)((val>>1)&1));

        RtlZeroMemory(&mbi, sizeof(mbi));
        st = ZwQueryVirtualMemory(NtCurrentProcess(), va, 0, &mbi, sizeof(mbi), &r);
        KF("[probe2] query st=0x%X state=0x%X protect=0x%X type=0x%X\n",
           st, mbi.State, mbi.Protect, mbi.Type);
    }

    KeUnstackDetachProcess(&apc);
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl, ct, ct2; ULONG waited=0, pid=0, last=0, stable=0;
    PEPROCESS proc=NULL; NTSTATUS st; UNREFERENCED_PARAMETER(ctx);
    ct.QuadPart=0; K("[probe2] waiter alive\n");
    for(;;){
        pid=FindPid(L"r5apex_dx12.exe",&ct2);
        if(pid&&pid==last&&ct2.QuadPart==ct.QuadPart) stable+=500; else { last=pid; ct=ct2; stable=0; }
        if(pid&&stable>=(ULONG)SETTLE_SEC*1000) break;
        dl.QuadPart=-5000000LL; KeDelayExecutionThread(KernelMode,FALSE,&dl);
        waited+=500; if(waited>1800000){ K("[probe2] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); }
    }
    KF("[probe2] game pid=%lu\n", pid);
    st=PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid,&proc);
    if(!NT_SUCCESS(st)){ KF("[probe2] lookup=0x%X\n", st); PsTerminateSystemThread(st); }
    Probe(proc); ObDereferenceObject(proc);
    K("[probe2] done\n"); PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h=NULL; NTSTATUS st; UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    K("\n[probe2] === entry ===\n");
    st=PsCreateSystemThread(&h,THREAD_ALL_ACCESS,NULL,NULL,NULL,Waiter,NULL);
    if(NT_SUCCESS(st)&&h) ZwClose(h);
    { LARGE_INTEGER d; d.QuadPart=-30000000LL; KeDelayExecutionThread(KernelMode,FALSE,&d); }
    return STATUS_SUCCESS;
}

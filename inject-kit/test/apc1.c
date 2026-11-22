// apc1.sys -- APC 注入：把 kernel32!LoadLibraryW 作为用户态 APC 投递给游戏已有线程
#include <ntifs.h>
#include <ntstrsafe.h>

#define LOG_FILE L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define JOB_FILE L"\\??\\C:\\ProgramData\\kmap_job.txt"
#define SETTLE_SEC 32

NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T);
NTSYSAPI NTSTATUS NTAPI NtGetNextThread(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
NTKERNELAPI VOID NTAPI KeInitializeApc(PKAPC, PKTHREAD, KAPC_ENVIRONMENT, PKKERNEL_ROUTINE, PKRUNDOWN_ROUTINE, PKNORMAL_ROUTINE, KPROCESSOR_MODE, PVOID);

typedef struct _SPID { ULONG Next; ULONG Threads; LARGE_INTEGER W; ULONG HF; ULONG HW;
    ULONGLONG CT; LARGE_INTEGER Cr; LARGE_INTEGER U; LARGE_INTEGER K; UNICODE_STRING ImageName;
    LONG BP; HANDLE PID; } SPID, *PSPID;

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
      for(;;){ PSPID e=(PSPID)p;
        if(e->ImageName.Buffer&&e->ImageName.Length){ UNICODE_STRING u=e->ImageName;
            if(RtlEqualUnicodeString(&u,&want,TRUE)){ res=(ULONG)(ULONG_PTR)e->PID; if(oc)*oc=e->Cr; break; } }
        if(!e->Next) break; p+=e->Next; } }
    ExFreePoolWithTag(buf,'pmiK'); return res;
}
static BOOLEAN ReadJob(CHAR* dll, ULONG cch)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h; CHAR buf[512]; ULONG i=0,j=0;
    RtlInitUnicodeString(&p,JOB_FILE);
    InitializeObjectAttributes(&oa,&p,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,NULL,NULL);
    if(!NT_SUCCESS(ZwCreateFile(&h,GENERIC_READ|SYNCHRONIZE,&oa,&io,NULL,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ,FILE_OPEN,FILE_SYNCHRONOUS_IO_NONALERT,NULL,0))) return FALSE;
    RtlZeroMemory(buf,sizeof(buf)); ZwReadFile(h,NULL,NULL,NULL,&io,buf,sizeof(buf)-1,NULL,NULL); ZwClose(h);
    while(buf[i]&&buf[i]!='\r'&&buf[i]!='\n') i++;
    while(buf[i]=='\r'||buf[i]=='\n') i++;
    while(buf[i]&&buf[i]!='\r'&&buf[i]!='\n'&&j<cch-1) dll[j++]=buf[i++];
    dll[j]=0; return j>0;
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

static LONG_PTR g_res = 0;

static VOID Inject(PEPROCESS proc, ULONG pid, const CHAR* dllPath)
{
    KAPC_STATE apc; PVOID pathVa=NULL; SIZE_T ps=0x1000, done=0; NTSTATUS st;
    UNICODE_STRING us; WCHAR wpath[260]; ULONG64 k32, loadlib; ULONG posted=0;

    RtlStringCchPrintfW(wpath, RTL_NUMBER_OF(wpath), L"%S", dllPath);
    RtlInitUnicodeString(&us, wpath);

    KeStackAttachProcess(proc, &apc);
    st = ZwAllocateVirtualMemory(NtCurrentProcess(), &pathVa, 0, &ps, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    KeUnstackDetachProcess(&apc);
    KF("[apc1] alloc path st=0x%X va=0x%p\n", st, pathVa);
    if (!NT_SUCCESS(st) || !pathVa) return;

    st = MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)wpath, proc, pathVa, us.Length+2, KernelMode, &done);
    KF("[apc1] write st=0x%X n=%Iu\n", st, done);
    if (!NT_SUCCESS(st)) return;

    KeStackAttachProcess(proc, &apc);
    k32 = FindMod(L"kernel32.dll");
    loadlib = k32 ? (k32 + 0x3F6C0) : 0;
    KeUnstackDetachProcess(&apc);
    KF("[apc1] k32=0x%llX LoadLibraryW=0x%llX\n", k32, loadlib);
    if (!loadlib) return;

    /* 枚举线程并投递用户态 APC */
    {
        HANDLE ph = NULL, th = NULL, cur = NULL;
        OBJECT_ATTRIBUTES oa; CLIENT_ID cid;

        InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
        cid.UniqueThread = NULL;
        st = ZwOpenProcess(&ph, PROCESS_ALL_ACCESS, &oa, &cid);
        KF("[apc1] open proc st=0x%X h=%p\n", st, ph);
        if (!NT_SUCCESS(st)) return;

        for (;;)
        {
            HANDLE next = NULL;
            st = NtGetNextThread(ph, cur, THREAD_ALL_ACCESS, 0, 0, &next);
            if (!NT_SUCCESS(st) || next == NULL) break;
            if (cur) ZwClose(cur);
            cur = next;

            { PETHREAD te = NULL;
              if (NT_SUCCESS(ObReferenceObjectByHandle(cur, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&te, NULL)) && te) {
                  PKAPC apcobj = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), 'pmiK');
                  if (apcobj) {
                      KeInitializeApc(apcobj, te, OriginalApcEnvironment, NULL, NULL,
                                      (PKNORMAL_ROUTINE)(PVOID)loadlib, UserMode, pathVa);
                      if (KeInsertQueueApc(apcobj, pathVa, NULL, 0)) posted++;
                      else ExFreePoolWithTag(apcobj, 'pmiK');
                  }
                  ObDereferenceObject(te);
              } }
            if (posted > 40) break;
        }
        if (cur) ZwClose(cur);
        ZwClose(ph);
    }
    KF("[apc1] apc posted=%lu\n", posted);

    { LARGE_INTEGER d; d.QuadPart=-50000000LL; KeDelayExecutionThread(KernelMode,FALSE,&d); }

    KeStackAttachProcess(proc, &apc);
    { WCHAR base[64]; ULONG i=us.Length/2, j=0; UNICODE_STRING nm;
      while(i>0 && wpath[i-1]!=L'\\') i--;
      while(i<us.Length/2 && j<63) base[j++]=wpath[i++];
      base[j]=0;
      RtlInitUnicodeString(&nm, base);
      { ULONG64 b = FindMod(base);
        KF("[apc1] inLdr=%d base=0x%llX (%S)\n", b!=0, b, base); } }
    KeUnstackDetachProcess(&apc);
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl,ct,ct2; ULONG waited=0,pid=0,last=0,stable=0; PEPROCESS proc=NULL; NTSTATUS st;
    CHAR dll[260]; UNREFERENCED_PARAMETER(ctx); ct.QuadPart=0; K("[apc1] waiter alive\n");
    if(!ReadJob(dll,sizeof(dll))){ K("[apc1] job fail\n"); PsTerminateSystemThread(STATUS_UNSUCCESSFUL); }
    KF("[apc1] dll=%s\n", dll);
    for(;;){ pid=FindPid(L"r5apex_dx12.exe",&ct2);
        if(pid&&pid==last&&ct2.QuadPart==ct.QuadPart) stable+=500; else { last=pid; ct=ct2; stable=0; }
        if(pid&&stable>=(ULONG)SETTLE_SEC*1000) break;
        dl.QuadPart=-5000000LL; KeDelayExecutionThread(KernelMode,FALSE,&dl); waited+=500;
        if(waited>1800000){ K("[apc1] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); } }
    KF("[apc1] game pid=%lu\n", pid);
    st=PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid,&proc);
    if(!NT_SUCCESS(st)){ KF("[apc1] lookup=0x%X\n",st); PsTerminateSystemThread(st); }
    Inject(proc,pid,dll); ObDereferenceObject(proc);
    K("[apc1] done\n"); PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h=NULL; NTSTATUS st; UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    K("\n[apc1] === entry ===\n");
    st=PsCreateSystemThread(&h,THREAD_ALL_ACCESS,NULL,NULL,NULL,Waiter,NULL);
    if(NT_SUCCESS(st)&&h) ZwClose(h);
    { LARGE_INTEGER d; d.QuadPart=-30000000LL; KeDelayExecutionThread(KernelMode,FALSE,&d); }
    return STATUS_SUCCESS;
}

// kinject12.sys -- 用 MmCopyVirtualMemory 写入路径（正确处理 demand-zero 缺页），
//                  然后 RtlCreateUserThread(LoadLibraryW) 注入
#include <ntifs.h>
#include <ntstrsafe.h>

#define LOG_FILE L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define JOB_FILE L"\\??\\C:\\ProgramData\\kmap_job.txt"
#define SETTLE_SEC 32

NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI RtlCreateUserThread(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PVOID);
NTSYSAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T);

typedef struct _SPIB { ULONG Next; ULONG Threads; LARGE_INTEGER W; ULONG HF; ULONG HW;
    ULONGLONG CT; LARGE_INTEGER Cr; LARGE_INTEGER U; LARGE_INTEGER K; UNICODE_STRING ImageName;
    LONG BP; HANDLE PID; } SPIB, *PSPIB;

static VOID WA(PCWSTR file, PCSTR t, ULONG len)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    RtlInitUnicodeString(&p, file);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);
    if(!NT_SUCCESS(ZwCreateFile(&h, FILE_APPEND_DATA|SYNCHRONIZE, &oa, &io, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0))) return;
    ZwWriteFile(h, NULL, NULL, NULL, &io, (PVOID)t, len, NULL, NULL);
    ZwFlushBuffersFile(h, &io); ZwClose(h);
}
static VOID K(PCSTR t){ size_t n=0; RtlStringCchLengthA(t,2048,&n); WA(LOG_FILE,t,(ULONG)n); }
static VOID KF(PCSTR f,...){ CHAR b[400]; va_list ap; va_start(ap,f); RtlStringCchVPrintfA(b,sizeof(b),f,ap); va_end(ap); K(b); }

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
      for(;;){ PSPIB e=(PSPIB)p;
        if(e->ImageName.Buffer&&e->ImageName.Length){ UNICODE_STRING u=e->ImageName;
            if(RtlEqualUnicodeString(&u,&want,TRUE)){ res=(ULONG)(ULONG_PTR)e->PID; if(oc)*oc=e->Cr; break; } }
        if(!e->Next) break; p+=e->Next; } }
    ExFreePoolWithTag(buf,'pmiK');
    return res;
}

static BOOLEAN ReadJob(CHAR* dll, ULONG cch)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h; CHAR buf[512]; ULONG i=0,j=0;
    RtlInitUnicodeString(&p, JOB_FILE);
    InitializeObjectAttributes(&oa,&p,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,NULL,NULL);
    if(!NT_SUCCESS(ZwCreateFile(&h, GENERIC_READ|SYNCHRONIZE, &oa,&io,NULL,FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL,0))) return FALSE;
    RtlZeroMemory(buf,sizeof(buf));
    ZwReadFile(h,NULL,NULL,NULL,&io,buf,sizeof(buf)-1,NULL,NULL);
    ZwClose(h);
    while(i<sizeof(buf)&&buf[i]&&buf[i]!='\r'&&buf[i]!='\n') i++;   /* 第一行=镜像名 */
    while(i<sizeof(buf)&&(buf[i]=='\r'||buf[i]=='\n')) i++;
    while(i<sizeof(buf)&&buf[i]&&buf[i]!='\r'&&buf[i]!='\n'&&j<cch-1) dll[j++]=buf[i++];
    dll[j]=0;
    return j>0;
}

static ULONG64 FindMod(PCWSTR want)
{
    PPEB peb=(PPEB)PsGetProcessPeb(PsGetCurrentProcess()); PVOID ldr; LIST_ENTRY* head; LIST_ENTRY* cur;
    UNICODE_STRING w;
    if(!peb) return 0;
    ldr=*(PVOID*)((PUCHAR)peb+0x18); if(!ldr) return 0;
    head=(LIST_ENTRY*)((PUCHAR)ldr+0x10);
    RtlInitUnicodeString(&w,want);
    for(cur=head->Flink; cur!=head&&cur; cur=cur->Flink){
        PUCHAR e=(PUCHAR)cur; UNICODE_STRING bn;
        bn.Length=*(USHORT*)(e+0x58); bn.MaximumLength=bn.Length; bn.Buffer=*(PWCH*)(e+0x60);
        if(bn.Buffer&&bn.Length&&RtlEqualUnicodeString(&bn,&w,TRUE)) return *(ULONG64*)(e+0x30);
    }
    return 0;
}

static VOID Inject(PEPROCESS proc, const CHAR* dllPath)
{
    KAPC_STATE apc; PVOID pathVa=NULL, resVa=NULL; SIZE_T ps=0x1000, rs=0x10, done=0;
    NTSTATUS st; UNICODE_STRING us; WCHAR wpath[260];
    ULONG64 k32, loadlib;

    RtlStringCchPrintfW(wpath, RTL_NUMBER_OF(wpath), L"%S", dllPath);
    RtlInitUnicodeString(&us, wpath);

    KeStackAttachProcess(proc, &apc);
    st = ZwAllocateVirtualMemory(NtCurrentProcess(), &pathVa, 0, &ps, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    KF("[kinject12] alloc path st=0x%X va=0x%p\n", st, pathVa);
    if (NT_SUCCESS(st)) {
        st = ZwAllocateVirtualMemory(NtCurrentProcess(), &resVa, 0, &rs, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        KF("[kinject12] alloc res st=0x%X va=0x%p\n", st, resVa);
    }
    KeUnstackDetachProcess(&apc);
    if (!NT_SUCCESS(st) || pathVa == NULL) return;

    /* 用 MmCopyVirtualMemory 写入：正确处理 demand-zero 缺页 */
    st = MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)wpath, proc, pathVa, us.Length + 2,
                             KernelMode, &done);
    KF("[kinject12] write path st=0x%X written=%Iu\n", st, done);
    if (!NT_SUCCESS(st)) return;

    /* 找到 kernel32!LoadLibraryW */
    KeStackAttachProcess(proc, &apc);
    k32 = FindMod(L"kernel32.dll");
    loadlib = 0;
    if (k32) {
        /* 从导出表解 LoadLibraryW（简单起见用固定 RVA，随构建变化时回退 0） */
        loadlib = k32 + 0x3F6C0;
    }
    KF("[kinject12] k32=0x%llX LoadLibraryW=0x%llX\n", k32, loadlib);
    if (loadlib) {
        HANDLE th = NULL;
        st = RtlCreateUserThread(NtCurrentProcess(), NULL, FALSE, 0, 0, 0, (PVOID)(ULONG_PTR)loadlib, pathVa, &th, NULL);
        KF("[kinject12] RtlCreateUserThread st=0x%X\n", st);
        if (NT_SUCCESS(st) && th) ZwClose(th);
    }
    KeUnstackDetachProcess(&apc);

    { LARGE_INTEGER d; d.QuadPart = -40000000LL; KeDelayExecutionThread(KernelMode, FALSE, &d); }

    /* 回读：模块是否进了 Ldr */
    KeStackAttachProcess(proc, &apc);
    {
        UNICODE_STRING nm; WCHAR base[64]; ULONG i=us.Length/2, j=0;
        while (i > 0 && wpath[i-1] != L'\\') i--;
        while (i < us.Length/2 && j < 63) base[j++] = wpath[i++];
        base[j] = 0;
        RtlInitUnicodeString(&nm, base);
        {
            ULONG64 b = FindMod(base);
            KF("[kinject12] inLdr=%d base=0x%llX (%S)\n", b != 0, b, base);
        }
    }
    KeUnstackDetachProcess(&apc);
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl, ct, ct2; ULONG waited=0, pid=0, last=0, stable=0;
    PEPROCESS proc=NULL; NTSTATUS st; CHAR dll[260]; UNREFERENCED_PARAMETER(ctx);
    ct.QuadPart=0; K("[kinject12] waiter alive\n");
    if (!ReadJob(dll, sizeof(dll))) { K("[kinject12] job read failed\n"); PsTerminateSystemThread(STATUS_UNSUCCESSFUL); }
    KF("[kinject12] dll=%s\n", dll);
    for(;;){
        pid=FindPid(L"r5apex_dx12.exe",&ct2);
        if(pid&&pid==last&&ct2.QuadPart==ct.QuadPart) stable+=500; else { last=pid; ct=ct2; stable=0; }
        if(pid&&stable>=(ULONG)SETTLE_SEC*1000) break;
        dl.QuadPart=-5000000LL; KeDelayExecutionThread(KernelMode,FALSE,&dl);
        waited+=500; if(waited>1800000){ K("[kinject12] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); }
    }
    KF("[kinject12] game pid=%lu\n", pid);
    st=PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid,&proc);
    if(!NT_SUCCESS(st)){ KF("[kinject12] lookup=0x%X\n", st); PsTerminateSystemThread(st); }
    Inject(proc, dll);
    ObDereferenceObject(proc);
    K("[kinject12] done\n"); PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h=NULL; NTSTATUS st; UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    K("\n[kinject12] === entry ===\n");
    st=PsCreateSystemThread(&h,THREAD_ALL_ACCESS,NULL,NULL,NULL,Waiter,NULL);
    if(NT_SUCCESS(st)&&h) ZwClose(h);
    { LARGE_INTEGER d; d.QuadPart=-30000000LL; KeDelayExecutionThread(KernelMode,FALSE,&d); }
    return STATUS_SUCCESS;
}

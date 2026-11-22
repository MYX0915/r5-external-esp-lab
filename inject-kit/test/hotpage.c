// hotpage.sys -- 纯读：找出游戏进程里"频繁变化"的 RW 私有页（shellcode 落脚点候选）
#include <ntifs.h>
#include <ntstrsafe.h>

#define LOG_FILE L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define SETTLE_SEC 20

NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
NTSYSAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T);

typedef struct _SPIG { ULONG Next; ULONG Threads; LARGE_INTEGER W; ULONG HF; ULONG HW;
    ULONGLONG CT; LARGE_INTEGER Cr; LARGE_INTEGER U; LARGE_INTEGER K; UNICODE_STRING ImageName;
    LONG BP; HANDLE PID; } SPIG, *PSPIG;

typedef struct _MBI3 { PVOID Base; PVOID AllocBase; ULONG AllocProt; ULONG P1; SIZE_T Size;
    ULONG State; ULONG Protect; ULONG Type; ULONG P2; } MBI3;

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
      for(;;){ PSPIG e=(PSPIG)p;
        if(e->ImageName.Buffer&&e->ImageName.Length){ UNICODE_STRING u=e->ImageName;
            if(RtlEqualUnicodeString(&u,&want,TRUE)){ res=(ULONG)(ULONG_PTR)e->PID; if(oc)*oc=e->Cr; break; } }
        if(!e->Next) break; p+=e->Next; } }
    ExFreePoolWithTag(buf,'pmiK'); return res;
}

static VOID Scan(PEPROCESS proc)
{
    PVOID a = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x1000, 'pmiK');
    PVOID b = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x1000, 'pmiK');
    KAPC_STATE apc; ULONG64 addr = 0x10000; ULONG scanned = 0, hot = 0;

    if (!a || !b) { if(a) ExFreePoolWithTag(a,'pmiK'); if(b) ExFreePoolWithTag(b,'pmiK'); return; }

    KeStackAttachProcess(proc, &apc);
    while (addr < 0x00007FFFFFFF0000ULL && scanned < 600)
    {
        MBI3 m; SIZE_T r=0; NTSTATUS st;
        RtlZeroMemory(&m, sizeof(m));
        st = ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)(ULONG_PTR)addr, 0, &m, sizeof(m), &r);
        if (!NT_SUCCESS(st) || m.Size == 0) { addr += 0x10000; continue; }

        if (m.State == 0x1000 && (m.Protect & 0xFF) == 0x04 && m.Type == 0x20000 && m.Size >= 0x1000)
        {
            SIZE_T got=0, got2=0, len = min(m.Size, 0x1000);
            st = MmCopyVirtualMemory(proc, m.Base, PsGetCurrentProcess(), a, len, KernelMode, &got);
            if (NT_SUCCESS(st) && got == len)
            {
                LARGE_INTEGER d; d.QuadPart = -2000000LL;   /* 20ms */
                KeDelayExecutionThread(KernelMode, FALSE, &d);
                st = MmCopyVirtualMemory(proc, m.Base, PsGetCurrentProcess(), b, len, KernelMode, &got2);
                if (NT_SUCCESS(st) && got2 == len)
                {
                    ULONG i, diff = 0;
                    PUCHAR pa=(PUCHAR)a, pb=(PUCHAR)b;
                    for (i=0;i<len;i++) if (pa[i]!=pb[i]) diff++;
                    if (diff > len/10)
                    {
                        hot++;
                        KF("[hot] 0x%p size=0x%IX 变化=%lu/%Iu\n", m.Base, m.Size, diff, len);
                    }
                }
            }
            scanned++;
        }
        addr = (ULONG64)m.Base + m.Size;
    }
    KeUnstackDetachProcess(&apc);
    ExFreePoolWithTag(a,'pmiK'); ExFreePoolWithTag(b,'pmiK');
    KF("[hot] scanned=%lu hot=%lu\n", scanned, hot);
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl,ct,ct2; ULONG waited=0,pid=0,last=0,stable=0; PEPROCESS proc=NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(ctx); ct.QuadPart=0; K("[hot] waiter alive\n");
    for(;;){ pid=FindPid(L"r5apex_dx12.exe",&ct2);
        if(pid&&pid==last&&ct2.QuadPart==ct.QuadPart) stable+=500; else { last=pid; ct=ct2; stable=0; }
        if(pid&&stable>=(ULONG)SETTLE_SEC*1000) break;
        dl.QuadPart=-5000000LL; KeDelayExecutionThread(KernelMode,FALSE,&dl); waited+=500;
        if(waited>1800000){ K("[hot] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); } }
    KF("[hot] game pid=%lu\n", pid);
    st=PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid,&proc);
    if(!NT_SUCCESS(st)){ KF("[hot] lookup=0x%X\n",st); PsTerminateSystemThread(st); }
    Scan(proc); ObDereferenceObject(proc);
    K("[hot] done\n"); PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h=NULL; NTSTATUS st; UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    K("\n[hot] === entry ===\n");
    st=PsCreateSystemThread(&h,THREAD_ALL_ACCESS,NULL,NULL,NULL,Waiter,NULL);
    if(NT_SUCCESS(st)&&h) ZwClose(h);
    { LARGE_INTEGER d; d.QuadPart=-30000000LL; KeDelayExecutionThread(KernelMode,FALSE,&d); }
    return STATUS_SUCCESS;
}
